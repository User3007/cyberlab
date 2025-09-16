"""
Encryption Types Cryptography Component
Comprehensive guide to modern encryption methods - 2024 Enhanced
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import numpy as np
from typing import Dict, List, Any, Optional
import hashlib
import base64

# Import shared utilities
from ...shared.color_schemes import CRYPTOGRAPHY_COLORS
from ...shared.ui_components import create_banner, create_takeaways, create_info_card, create_cheat_sheet_tabs
from ...shared.diagram_utils import create_basic_figure
from ...templates.component_template import ComponentTemplate


class EncryptionTypesComponent(ComponentTemplate):
    """Encryption Types component with latest 2024 cryptographic standards"""
    
    def __init__(self):
        super().__init__(
            component_name="🔐 Encryption Types",
            description="Comprehensive guide to symmetric, asymmetric, and quantum-resistant encryption",
            color_scheme=CRYPTOGRAPHY_COLORS,
            estimated_time="45 minutes"
        )
        
        self.set_prerequisites([
            "Basic mathematics understanding",
            "Familiarity with computer science concepts",
            "Understanding of security principles"
        ])
        
        self.set_learning_objectives([
            "Master symmetric vs asymmetric encryption differences",
            "Understand modern encryption algorithms and their applications",
            "Explore quantum-resistant cryptography preparations",
            "Apply encryption best practices in real-world scenarios",
            "Evaluate encryption performance and security trade-offs"
        ])
        
        self.set_key_concepts([
            "Symmetric Encryption", "Asymmetric Encryption", "Hybrid Cryptosystems",
            "Key Management", "Quantum Resistance", "Performance Analysis"
        ])
    
    def render_content(self):
        """Render the Encryption Types content"""
        
        # Encryption overview
        self._render_encryption_overview()
        
        # Interactive encryption comparison
        self._render_encryption_comparison()
        
        # Hands-on encryption demo
        self._render_encryption_demo()
        
        # Modern algorithms deep dive
        self._render_modern_algorithms()
        
        # Quantum cryptography
        self._render_quantum_cryptography()
        
        # Comprehensive cheat sheets
        self._render_cheat_sheets()
    
    def _render_encryption_overview(self):
        """Render encryption overview"""
        st.subheader("🔐 Encryption Types Overview")
        
        # Enhanced visual banner with 2024 context
        st.markdown("""
        <div style="background: linear-gradient(135deg, #a55eea 0%, #8854d0 100%); padding: 2rem; border-radius: 12px; margin-bottom: 1.5rem; color: white; text-align: center;">
            <h2 style="margin: 0 0 0.5rem 0;">🌐 Modern Cryptography Landscape 2024</h2>
            <p style="margin: 0; opacity: 0.9; font-size: 1.1rem;">
                Quantum-Ready • Post-Quantum Standards • Zero-Trust Encryption
            </p>
            <p style="margin: 0.5rem 0 0 0; opacity: 0.8; font-size: 0.9rem;">
                "Preparing for the quantum computing era"
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # Encryption classification
        encryption_types = {
            "Symmetric Encryption": {
                "description": "Same key for encryption and decryption",
                "key_characteristic": "Single shared secret key",
                "speed": "Very Fast (1000x faster than asymmetric)",
                "key_management": "Complex (n(n-1)/2 keys for n users)",
                "use_cases": ["Bulk data encryption", "Database encryption", "File system encryption"],
                "algorithms": ["AES-256", "ChaCha20", "Salsa20", "Camellia"],
                "quantum_resistance": "Vulnerable (Grover's algorithm reduces key strength by half)"
            },
            "Asymmetric Encryption": {
                "description": "Different keys for encryption and decryption",
                "key_characteristic": "Public-private key pairs",
                "speed": "Slow (1000x slower than symmetric)",
                "key_management": "Simple (2n keys for n users)",
                "use_cases": ["Key exchange", "Digital signatures", "Authentication"],
                "algorithms": ["RSA-4096", "ECC P-384", "Ed25519", "X25519"],
                "quantum_resistance": "Vulnerable (Shor's algorithm breaks current algorithms)"
            },
            "Hybrid Cryptosystems": {
                "description": "Combination of symmetric and asymmetric encryption",
                "key_characteristic": "Best of both worlds approach",
                "speed": "Fast (asymmetric for key exchange, symmetric for data)",
                "key_management": "Balanced (leverages asymmetric for key distribution)",
                "use_cases": ["TLS/SSL", "Email encryption", "VPN tunnels"],
                "algorithms": ["RSA+AES", "ECDH+ChaCha20", "X25519+AES-GCM"],
                "quantum_resistance": "Partially vulnerable (asymmetric component at risk)"
            },
            "Post-Quantum Cryptography": {
                "description": "Quantum-resistant encryption algorithms",
                "key_characteristic": "Resistant to quantum computer attacks",
                "speed": "Variable (generally slower than current methods)",
                "key_management": "Complex (larger key sizes, new protocols)",
                "use_cases": ["Future-proof systems", "Long-term data protection"],
                "algorithms": ["CRYSTALS-Kyber", "CRYSTALS-Dilithium", "FALCON", "SPHINCS+"],
                "quantum_resistance": "Designed to be quantum-resistant"
            }
        }
        
        # Interactive type selector
        selected_type = st.selectbox(
            "🔍 Explore Encryption Type:",
            list(encryption_types.keys()),
            help="Select an encryption type to see detailed analysis",
            key="encryption_type_selector"
        )
        
        type_info = encryption_types[selected_type]
        
        # Enhanced type display
        create_info_card(
            f"🔐 {selected_type}",
            type_info['description'],
            card_type="primary",
            color_scheme=self.color_scheme
        )
        
        # Detailed characteristics
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**🔑 Key Characteristics:**")
            st.markdown(f"• **Key Model:** {type_info['key_characteristic']}")
            st.markdown(f"• **Speed:** {type_info['speed']}")
            st.markdown(f"• **Key Management:** {type_info['key_management']}")
        
        with col2:
            st.markdown("**🛡️ Security & Applications:**")
            st.markdown(f"• **Quantum Resistance:** {type_info['quantum_resistance']}")
            st.markdown("• **Primary Use Cases:**")
            for use_case in type_info['use_cases']:
                st.markdown(f"  - {use_case}")
        
        # Modern algorithms
        st.markdown("**🔧 Modern Algorithms (2024):**")
        for algorithm in type_info['algorithms']:
            st.markdown(f"• **{algorithm}**")
    
    def _render_encryption_comparison(self):
        """Render interactive encryption comparison"""
        st.subheader("⚖️ Encryption Performance Comparison")
        
        # Performance comparison data (2024 benchmarks)
        performance_data = {
            "Algorithm": [
                "AES-256 (Symmetric)", "ChaCha20 (Symmetric)", "RSA-4096 (Asymmetric)",
                "ECC P-384 (Asymmetric)", "CRYSTALS-Kyber (Post-Quantum)", "CRYSTALS-Dilithium (Post-Quantum)"
            ],
            "Encryption Speed (MB/s)": [1500, 2000, 0.5, 2.0, 800, 1.2],
            "Key Size (bits)": [256, 256, 4096, 384, 1632, 2420],
            "Security Level": [128, 128, 112, 192, 128, 128],
            "Quantum Resistant": ["No", "No", "No", "No", "Yes", "Yes"],
            "Year Standardized": [2001, 2008, 1977, 2005, 2022, 2022]
        }
        
        df = pd.DataFrame(performance_data)
        
        # Interactive comparison charts
        comparison_metric = st.selectbox(
            "📊 Select Comparison Metric:",
            ["Encryption Speed (MB/s)", "Key Size (bits)", "Security Level"],
            key="comparison_metric_selector"
        )
        
        fig = px.bar(
            df,
            x="Algorithm",
            y=comparison_metric,
            color="Quantum Resistant",
            title=f"Encryption Algorithms - {comparison_metric} Comparison",
            color_discrete_map={"Yes": self.color_scheme['success'], "No": self.color_scheme['warning']}
        )
        
        fig.update_layout(
            xaxis_tickangle=-45,
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Detailed comparison table
        st.markdown("#### 📋 Detailed Algorithm Comparison")
        st.dataframe(df, use_container_width=True)
        
        # Algorithm selection and analysis
        if st.button("🔍 Analyze Algorithm Selection"):
            self._render_algorithm_selection_guide()
    
    def _render_algorithm_selection_guide(self):
        """Render algorithm selection guide"""
        st.markdown("#### 🎯 Algorithm Selection Guide")
        
        selection_criteria = {
            "High Performance Required": {
                "recommendation": "ChaCha20 (Symmetric)",
                "reason": "Fastest encryption speed, optimized for software implementation",
                "use_case": "Real-time communications, streaming data"
            },
            "Maximum Security": {
                "recommendation": "AES-256 + ECC P-384",
                "reason": "Proven security, hardware acceleration available",
                "use_case": "Government communications, financial transactions"
            },
            "Future-Proof (Quantum Safe)": {
                "recommendation": "CRYSTALS-Kyber + CRYSTALS-Dilithium",
                "reason": "NIST-approved post-quantum algorithms",
                "use_case": "Long-term data storage, critical infrastructure"
            },
            "Legacy Compatibility": {
                "recommendation": "RSA-2048 + AES-128",
                "reason": "Widely supported, good balance of security and performance",
                "use_case": "Existing systems, broad compatibility needs"
            },
            "Mobile/IoT Devices": {
                "recommendation": "X25519 + ChaCha20-Poly1305",
                "reason": "Low power consumption, efficient on ARM processors",
                "use_case": "Mobile apps, IoT devices, embedded systems"
            }
        }
        
        for scenario, info in selection_criteria.items():
            with st.expander(f"📱 {scenario}"):
                st.markdown(f"**🏆 Recommendation:** {info['recommendation']}")
                st.markdown(f"**💡 Reason:** {info['reason']}")
                st.markdown(f"**🎯 Use Case:** {info['use_case']}")
    
    def _render_encryption_demo(self):
        """Render hands-on encryption demonstration"""
        st.subheader("🧪 Interactive Encryption Demo")
        
        # Demo type selector
        demo_type = st.selectbox(
            "🔧 Select Demo Type:",
            ["Symmetric Encryption (AES-like)", "Hash Function Demo", "Key Exchange Simulation"],
            key="demo_type_selector"
        )
        
        if demo_type == "Symmetric Encryption (AES-like)":
            self._render_symmetric_demo()
        elif demo_type == "Hash Function Demo":
            self._render_hash_demo()
        elif demo_type == "Key Exchange Simulation":
            self._render_key_exchange_demo()
    
    def _render_symmetric_demo(self):
        """Render symmetric encryption demonstration"""
        st.markdown("#### 🔐 Symmetric Encryption Demonstration")
        
        # Input controls
        col1, col2 = st.columns(2)
        
        with col1:
            plaintext = st.text_area(
                "📝 Enter message to encrypt:",
                value="Hello, this is a secret message!",
                height=100
            )
        
        with col2:
            encryption_key = st.text_input(
                "🔑 Enter encryption key:",
                value="my_secret_key_2024",
                type="password"
            )
        
        if st.button("🚀 Encrypt Message"):
            # Simple demonstration (not production-grade)
            encrypted_message = self._simple_encrypt(plaintext, encryption_key)
            
            st.markdown("#### 📊 Encryption Results")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown("**📝 Original Message:**")
                st.code(plaintext, language='text')
            
            with col2:
                st.markdown("**🔐 Encrypted Message:**")
                st.code(encrypted_message, language='text')
            
            with col3:
                st.markdown("**🔓 Decrypted Message:**")
                decrypted_message = self._simple_decrypt(encrypted_message, encryption_key)
                st.code(decrypted_message, language='text')
            
            # Analysis
            st.markdown("#### 📈 Encryption Analysis")
            
            original_length = len(plaintext.encode('utf-8'))
            encrypted_length = len(encrypted_message.encode('utf-8'))
            
            analysis_data = {
                "Metric": ["Original Size", "Encrypted Size", "Size Overhead", "Character Set"],
                "Value": [
                    f"{original_length} bytes",
                    f"{encrypted_length} bytes", 
                    f"{((encrypted_length - original_length) / original_length * 100):.1f}%",
                    "Base64 (64 characters)"
                ]
            }
            
            analysis_df = pd.DataFrame(analysis_data)
            st.dataframe(analysis_df, use_container_width=True)
    
    def _simple_encrypt(self, plaintext: str, key: str) -> str:
        """Simple encryption for demonstration (NOT for production use)"""
        # Create a simple XOR-based encryption for demo purposes
        key_hash = hashlib.sha256(key.encode()).digest()
        plaintext_bytes = plaintext.encode('utf-8')
        
        encrypted_bytes = bytearray()
        for i, byte in enumerate(plaintext_bytes):
            encrypted_bytes.append(byte ^ key_hash[i % len(key_hash)])
        
        return base64.b64encode(encrypted_bytes).decode('utf-8')
    
    def _simple_decrypt(self, encrypted_text: str, key: str) -> str:
        """Simple decryption for demonstration (NOT for production use)"""
        try:
            key_hash = hashlib.sha256(key.encode()).digest()
            encrypted_bytes = base64.b64decode(encrypted_text.encode('utf-8'))
            
            decrypted_bytes = bytearray()
            for i, byte in enumerate(encrypted_bytes):
                decrypted_bytes.append(byte ^ key_hash[i % len(key_hash)])
            
            return decrypted_bytes.decode('utf-8')
        except:
            return "Decryption failed - check your key!"
    
    def _render_hash_demo(self):
        """Render hash function demonstration"""
        st.markdown("#### #️⃣ Hash Function Demonstration")
        
        input_text = st.text_area(
            "📝 Enter text to hash:",
            value="This is a sample message for hashing demonstration.",
            height=100
        )
        
        hash_algorithm = st.selectbox(
            "🔧 Select Hash Algorithm:",
            ["SHA-256", "SHA-512", "MD5 (deprecated)", "SHA-1 (deprecated)"],
            key="hash_algorithm_selector"
        )
        
        if st.button("🧮 Generate Hash"):
            # Generate hashes
            hash_results = {}
            
            if hash_algorithm == "SHA-256":
                hash_results["SHA-256"] = hashlib.sha256(input_text.encode()).hexdigest()
            elif hash_algorithm == "SHA-512":
                hash_results["SHA-512"] = hashlib.sha512(input_text.encode()).hexdigest()
            elif hash_algorithm == "MD5 (deprecated)":
                hash_results["MD5"] = hashlib.md5(input_text.encode()).hexdigest()
            elif hash_algorithm == "SHA-1 (deprecated)":
                hash_results["SHA-1"] = hashlib.sha1(input_text.encode()).hexdigest()
            
            # Display results
            st.markdown("#### 📊 Hash Results")
            
            for algo, hash_value in hash_results.items():
                st.markdown(f"**{algo} Hash:**")
                st.code(hash_value, language='text')
            
            # Hash properties demonstration
            st.markdown("#### 🔍 Hash Properties Demonstration")
            
            # Show avalanche effect
            modified_text = input_text + "."
            original_hash = hashlib.sha256(input_text.encode()).hexdigest()
            modified_hash = hashlib.sha256(modified_text.encode()).hexdigest()
            
            # Calculate bit differences
            original_bits = bin(int(original_hash, 16))[2:].zfill(256)
            modified_bits = bin(int(modified_hash, 16))[2:].zfill(256)
            bit_differences = sum(o != m for o, m in zip(original_bits, modified_bits))
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Original Hash:**")
                st.code(original_hash, language='text')
            
            with col2:
                st.markdown("**Modified Hash (added '.'):**")
                st.code(modified_hash, language='text')
            
            st.metric("Bit Differences", f"{bit_differences}/256", f"{(bit_differences/256)*100:.1f}%")
            st.info("💡 **Avalanche Effect:** Small input changes cause large output changes (~50% bit difference)")
    
    def _render_key_exchange_demo(self):
        """Render key exchange simulation"""
        st.markdown("#### 🤝 Diffie-Hellman Key Exchange Simulation")
        
        st.markdown("""
        **Concept:** Two parties can establish a shared secret over an insecure channel without 
        exchanging the secret directly.
        """)
        
        # Parameters
        col1, col2 = st.columns(2)
        
        with col1:
            p = st.number_input("Prime number (p):", min_value=100, max_value=10000, value=23)
        with col2:
            g = st.number_input("Generator (g):", min_value=2, max_value=100, value=5)
        
        # Private keys
        alice_private = st.slider("Alice's private key:", 1, 20, 6)
        bob_private = st.slider("Bob's private key:", 1, 20, 15)
        
        if st.button("🔄 Perform Key Exchange"):
            # Calculate public keys
            alice_public = pow(g, alice_private, p)
            bob_public = pow(g, bob_private, p)
            
            # Calculate shared secrets
            alice_shared = pow(bob_public, alice_private, p)
            bob_shared = pow(alice_public, bob_private, p)
            
            # Display process
            st.markdown("#### 🔄 Key Exchange Process")
            
            process_data = [
                {"Step": "1", "Alice": f"Private: {alice_private}", "Bob": f"Private: {bob_private}", "Public": "Parameters: p={p}, g={g}"},
                {"Step": "2", "Alice": f"Public: {g}^{alice_private} mod {p} = {alice_public}", "Bob": f"Public: {g}^{bob_private} mod {p} = {bob_public}", "Public": "Exchange public keys"},
                {"Step": "3", "Alice": f"Shared: {bob_public}^{alice_private} mod {p} = {alice_shared}", "Bob": f"Shared: {alice_public}^{bob_private} mod {p} = {bob_shared}", "Public": "Compute shared secret"}
            ]
            
            process_df = pd.DataFrame(process_data)
            st.dataframe(process_df, use_container_width=True)
            
            # Verify shared secret
            if alice_shared == bob_shared:
                st.success(f"✅ **Success!** Both parties computed the same shared secret: **{alice_shared}**")
            else:
                st.error("❌ **Error!** Shared secrets don't match - check calculations")
            
            st.info("🔐 **Security:** An eavesdropper knows p, g, Alice's public key, and Bob's public key, but cannot easily compute the shared secret without solving the discrete logarithm problem.")
    
    def _render_modern_algorithms(self):
        """Render modern encryption algorithms deep dive"""
        st.subheader("🚀 Modern Encryption Algorithms (2024)")
        
        modern_algorithms = {
            "AES-256-GCM": {
                "type": "Symmetric (Authenticated Encryption)",
                "key_size": "256 bits",
                "year": "2001 (GCM: 2007)",
                "strengths": ["Hardware acceleration", "Authenticated encryption", "Parallel processing"],
                "weaknesses": ["Quantum vulnerable", "Side-channel attacks possible"],
                "use_cases": ["TLS 1.3", "VPN tunnels", "Database encryption", "File system encryption"],
                "performance": "~1500 MB/s (AES-NI)",
                "security_level": "128-bit post-quantum, 256-bit classical",
                "implementation": "Widely supported, hardware accelerated"
            },
            "ChaCha20-Poly1305": {
                "type": "Symmetric (Authenticated Encryption)",
                "key_size": "256 bits",
                "year": "2008 (ChaCha20), 2005 (Poly1305)",
                "strengths": ["Software optimized", "Constant-time implementation", "No timing attacks"],
                "weaknesses": ["Quantum vulnerable", "Newer algorithm (less analysis)"],
                "use_cases": ["Mobile devices", "TLS 1.3", "WireGuard VPN", "Google Chrome"],
                "performance": "~2000 MB/s (software)",
                "security_level": "128-bit post-quantum, 256-bit classical",
                "implementation": "Growing support, especially mobile"
            },
            "X25519 (ECDH)": {
                "type": "Asymmetric (Key Exchange)",
                "key_size": "256 bits (equivalent to 3072-bit RSA)",
                "year": "2006 (Curve25519)",
                "strengths": ["Fast key generation", "Small key size", "Constant-time operations"],
                "weaknesses": ["Quantum vulnerable (Shor's algorithm)", "Single curve dependency"],
                "use_cases": ["TLS 1.3", "Signal Protocol", "SSH", "WireGuard"],
                "performance": "~2 MB/s key exchange",
                "security_level": "128-bit classical",
                "implementation": "Increasing adoption, modern protocols"
            },
            "Ed25519 (Signatures)": {
                "type": "Asymmetric (Digital Signatures)",
                "key_size": "256 bits (equivalent to 3072-bit RSA)",
                "year": "2011",
                "strengths": ["Fast verification", "Small signatures", "Deterministic"],
                "weaknesses": ["Quantum vulnerable", "Limited hardware support"],
                "use_cases": ["SSH keys", "Git commits", "Certificate signing", "Blockchain"],
                "performance": "~1.2 MB/s signing",
                "security_level": "128-bit classical",
                "implementation": "Growing in modern applications"
            }
        }
        
        # Algorithm selector
        selected_algorithm = st.selectbox(
            "🔧 Select Modern Algorithm:",
            list(modern_algorithms.keys()),
            key="modern_algorithm_selector"
        )
        
        algo_info = modern_algorithms[selected_algorithm]
        
        # Algorithm profile
        st.markdown(f"""
        <div style="background: {self.color_scheme['background']}; padding: 1.5rem; border-radius: 8px; margin: 1rem 0; border-left: 5px solid {self.color_scheme['primary']};">
            <h4 style="color: {self.color_scheme['primary']}; margin-top: 0;">🔧 {selected_algorithm} Profile</h4>
            <p><strong>Type:</strong> {algo_info['type']}</p>
            <p><strong>Key Size:</strong> {algo_info['key_size']}</p>
            <p><strong>Year:</strong> {algo_info['year']}</p>
            <p><strong>Performance:</strong> {algo_info['performance']}</p>
            <p><strong>Security Level:</strong> {algo_info['security_level']}</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Detailed analysis
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**✅ Strengths:**")
            for strength in algo_info['strengths']:
                st.markdown(f"• {strength}")
            
            st.markdown("**🎯 Use Cases:**")
            for use_case in algo_info['use_cases']:
                st.markdown(f"• {use_case}")
        
        with col2:
            st.markdown("**⚠️ Weaknesses:**")
            for weakness in algo_info['weaknesses']:
                st.markdown(f"• {weakness}")
            
            st.markdown("**📊 Implementation Status:**")
            st.markdown(f"• {algo_info['implementation']}")
    
    def _render_quantum_cryptography(self):
        """Render quantum cryptography section"""
        st.subheader("🌌 Quantum Cryptography & Post-Quantum Algorithms")
        
        # Quantum threat timeline
        st.markdown("#### ⏰ Quantum Computing Timeline & Threat Assessment")
        
        quantum_timeline = {
            "2024": {
                "status": "Current State",
                "quantum_computers": "~1000 qubits (IBM, Google)",
                "threat_level": "Low",
                "description": "Quantum computers exist but cannot break current cryptography",
                "recommendation": "Begin planning post-quantum migration"
            },
            "2030": {
                "status": "Projected",
                "quantum_computers": "~10,000 qubits",
                "threat_level": "Medium",
                "description": "May break some cryptographic systems, RSA-2048 at risk",
                "recommendation": "Implement hybrid classical/post-quantum systems"
            },
            "2035": {
                "status": "Estimated",
                "quantum_computers": "~100,000 qubits",
                "threat_level": "High",
                "description": "Can break RSA-4096, ECC-384, current asymmetric crypto",
                "recommendation": "Full migration to post-quantum cryptography required"
            },
            "2040+": {
                "status": "Long-term",
                "quantum_computers": "1M+ qubits",
                "threat_level": "Critical",
                "description": "Can break all current public-key cryptography efficiently",
                "recommendation": "Only quantum-resistant algorithms remain secure"
            }
        }
        
        # Timeline visualization
        years = list(quantum_timeline.keys())
        threat_levels = [1, 3, 4, 5]  # Low=1, Medium=3, High=4, Critical=5
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=years,
            y=threat_levels,
            mode='lines+markers',
            name='Quantum Threat Level',
            line=dict(color=self.color_scheme['danger'], width=3),
            marker=dict(size=10)
        ))
        
        fig.update_layout(
            title="Quantum Computing Threat Timeline",
            xaxis_title="Year",
            yaxis_title="Threat Level",
            yaxis=dict(
                tickmode='array',
                tickvals=[1, 2, 3, 4, 5],
                ticktext=['Low', 'Medium-Low', 'Medium', 'High', 'Critical']
            ),
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Timeline details
        for year, info in quantum_timeline.items():
            with st.expander(f"📅 {year} - {info['status']}"):
                st.markdown(f"**🖥️ Quantum Computers:** {info['quantum_computers']}")
                st.markdown(f"**⚠️ Threat Level:** {info['threat_level']}")
                st.markdown(f"**📝 Description:** {info['description']}")
                st.markdown(f"**💡 Recommendation:** {info['recommendation']}")
        
        # NIST Post-Quantum Standards
        st.markdown("#### 🏆 NIST Post-Quantum Cryptography Standards (2024)")
        
        nist_standards = {
            "CRYSTALS-Kyber": {
                "category": "Key Encapsulation Mechanism (KEM)",
                "security_assumption": "Learning With Errors (LWE)",
                "key_sizes": "Kyber-512 (128-bit), Kyber-768 (192-bit), Kyber-1024 (256-bit)",
                "performance": "Fast key generation and encapsulation",
                "use_case": "Key exchange, replacing RSA/ECDH",
                "standardized": "2022 (FIPS 203)"
            },
            "CRYSTALS-Dilithium": {
                "category": "Digital Signature Algorithm",
                "security_assumption": "Learning With Errors (LWE)",
                "key_sizes": "Dilithium-2 (128-bit), Dilithium-3 (192-bit), Dilithium-5 (256-bit)",
                "performance": "Moderate signing speed, fast verification",
                "use_case": "Digital signatures, replacing RSA/ECDSA",
                "standardized": "2022 (FIPS 204)"
            },
            "SPHINCS+": {
                "category": "Digital Signature Algorithm (Stateless)",
                "security_assumption": "Hash functions",
                "key_sizes": "Various parameter sets with different security levels",
                "performance": "Slow signing, fast verification",
                "use_case": "High-security signatures, long-term certificates",
                "standardized": "2022 (FIPS 205)"
            },
            "FALCON": {
                "category": "Digital Signature Algorithm (Compact)",
                "security_assumption": "NTRU lattices",
                "key_sizes": "FALCON-512 (128-bit), FALCON-1024 (256-bit)",
                "performance": "Fast signing and verification",
                "use_case": "Constrained environments, embedded systems",
                "standardized": "Under consideration"
            }
        }
        
        pq_algorithm = st.selectbox(
            "🔬 Explore Post-Quantum Algorithm:",
            list(nist_standards.keys()),
            key="post_quantum_algorithm_selector"
        )
        
        pq_info = nist_standards[pq_algorithm]
        
        create_info_card(
            f"🛡️ {pq_algorithm}",
            f"Category: {pq_info['category']}",
            card_type="info",
            color_scheme=self.color_scheme
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**🔬 Technical Details:**")
            st.markdown(f"• **Security Assumption:** {pq_info['security_assumption']}")
            st.markdown(f"• **Key Sizes:** {pq_info['key_sizes']}")
            st.markdown(f"• **Performance:** {pq_info['performance']}")
        
        with col2:
            st.markdown("**📊 Standardization:**")
            st.markdown(f"• **Status:** {pq_info['standardized']}")
            st.markdown(f"• **Use Case:** {pq_info['use_case']}")
    
    def _render_cheat_sheets(self):
        """Render comprehensive encryption cheat sheets"""
        st.subheader("📋 Encryption Cheat Sheets")
        
        cheat_sheets = {
            "Algorithm Quick Reference": {
                "commands": [
                    {"Algorithm": "AES-256-GCM", "Type": "Symmetric", "Key Size": "256-bit", "Speed": "Very Fast", "Quantum Safe": "No", "Use Case": "Bulk encryption"},
                    {"Algorithm": "ChaCha20-Poly1305", "Type": "Symmetric", "Key Size": "256-bit", "Speed": "Very Fast", "Quantum Safe": "No", "Use Case": "Mobile/streaming"},
                    {"Algorithm": "RSA-4096", "Type": "Asymmetric", "Key Size": "4096-bit", "Speed": "Slow", "Quantum Safe": "No", "Use Case": "Legacy systems"},
                    {"Algorithm": "X25519", "Type": "Key Exchange", "Key Size": "256-bit", "Speed": "Fast", "Quantum Safe": "No", "Use Case": "Modern protocols"},
                    {"Algorithm": "Ed25519", "Type": "Digital Signature", "Key Size": "256-bit", "Speed": "Fast", "Quantum Safe": "No", "Use Case": "Code signing"},
                    {"Algorithm": "CRYSTALS-Kyber", "Type": "Post-Quantum KEM", "Key Size": "1632-bit", "Speed": "Moderate", "Quantum Safe": "Yes", "Use Case": "Future systems"}
                ]
            },
            "Security Recommendations": {
                "commands": [
                    {"Scenario": "Web Applications", "Recommendation": "TLS 1.3 (X25519 + AES-256-GCM)", "Reason": "Modern, fast, widely supported", "Migration": "Immediate"},
                    {"Scenario": "File Encryption", "Recommendation": "AES-256-GCM + PBKDF2", "Reason": "Hardware acceleration, authenticated", "Migration": "Current standard"},
                    {"Scenario": "Database Encryption", "Recommendation": "AES-256-GCM (Transparent Data Encryption)", "Reason": "Performance, key management", "Migration": "Industry standard"},
                    {"Scenario": "Email Security", "Recommendation": "PGP with Ed25519 + AES-256", "Reason": "Forward secrecy, compact keys", "Migration": "Gradual adoption"},
                    {"Scenario": "Long-term Archives", "Recommendation": "Hybrid: Current + Post-Quantum", "Reason": "Future-proof protection", "Migration": "Plan now"},
                    {"Scenario": "IoT Devices", "Recommendation": "ChaCha20-Poly1305 + X25519", "Reason": "Low power, constant-time", "Migration": "New deployments"}
                ]
            },
            "Implementation Best Practices": {
                "commands": [
                    {"Practice": "Key Generation", "Requirement": "Cryptographically secure random numbers", "Tool": "OS random (/dev/urandom, CryptGenRandom)", "Avoid": "Predictable seeds, weak PRNGs"},
                    {"Practice": "Key Storage", "Requirement": "Hardware Security Modules (HSM)", "Tool": "AWS KMS, Azure Key Vault, HashiCorp Vault", "Avoid": "Plaintext keys, hardcoded keys"},
                    {"Practice": "Key Rotation", "Requirement": "Regular key updates", "Tool": "Automated key management systems", "Avoid": "Never rotating keys"},
                    {"Practice": "Algorithm Selection", "Requirement": "NIST-approved algorithms", "Tool": "Current FIPS standards", "Avoid": "Deprecated algorithms (MD5, SHA-1, DES)"},
                    {"Practice": "Implementation", "Requirement": "Audited cryptographic libraries", "Tool": "OpenSSL, libsodium, Bouncy Castle", "Avoid": "Custom crypto implementation"},
                    {"Practice": "Side-channel Protection", "Requirement": "Constant-time implementations", "Tool": "Specialized crypto libraries", "Avoid": "Timing-dependent operations"}
                ]
            }
        }
        
        create_cheat_sheet_tabs(cheat_sheets, self.color_scheme)


def explain_encryption_types():
    """Main function to render Encryption Types component"""
    component = EncryptionTypesComponent()
    
    # Summary points for the component
    summary_points = [
        "Symmetric encryption provides high performance for bulk data, while asymmetric enables secure key exchange",
        "Modern algorithms like ChaCha20-Poly1305 and X25519 offer better security and performance than legacy options",
        "Quantum computing poses a significant threat to current asymmetric cryptography by 2030-2035",
        "NIST has standardized post-quantum algorithms (CRYSTALS-Kyber, Dilithium) for quantum-resistant security",
        "Hybrid cryptosystems combining symmetric and asymmetric encryption provide the best balance of security and performance"
    ]
    
    # Additional resources with latest 2024 updates
    resources = [
        {
            "title": "NIST Post-Quantum Cryptography Standards",
            "description": "Official NIST standards for quantum-resistant algorithms",
            "url": "https://csrc.nist.gov/Projects/post-quantum-cryptography"
        },
        {
            "title": "Cryptography Engineering (3rd Edition)",
            "description": "Comprehensive guide to practical cryptographic implementation",
            "url": "https://www.schneier.com/books/cryptography_engineering/"
        },
        {
            "title": "OpenSSL Documentation",
            "description": "Industry-standard cryptographic library documentation",
            "url": "https://www.openssl.org/docs/"
        },
        {
            "title": "libsodium - Modern Cryptography Library",
            "description": "Easy-to-use, secure cryptographic library",
            "url": "https://libsodium.gitbook.io/doc/"
        },
        {
            "title": "IETF RFC 8446 - TLS 1.3",
            "description": "Latest Transport Layer Security protocol specification",
            "url": "https://tools.ietf.org/rfc/rfc8446.txt"
        },
        {
            "title": "Quantum Computing Impact on Cryptography (2024)",
            "description": "Latest research on quantum computing threats and timeline"
        }
    ]
    
    # Render the complete component
    component.render_full_component(summary_points, resources)
