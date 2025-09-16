import streamlit as st
import hashlib
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import qrcode
from PIL import Image
import io

def run_lab():
    """Cryptography Lab - Học về mã hóa và bảo mật"""
    
    st.title("🔐 Cryptography Lab")
    st.markdown("---")
    
    # Tabs cho các bài thực hành khác nhau
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🔤 Hash Functions", 
        "🔒 Symmetric Encryption",
        "🔑 Asymmetric Encryption", 
        "📝 Digital Signatures",
        "🔐 Password Security"
    ])
    
    with tab1:
        hash_functions_lab()
    
    with tab2:
        symmetric_encryption_lab()
    
    with tab3:
        asymmetric_encryption_lab()
        
    with tab4:
        digital_signatures_lab()
        
    with tab5:
        password_security_lab()

def hash_functions_lab():
    """Lab Hash Functions"""
    st.subheader("🔤 Hash Functions Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Hash functions chuyển đổi input có độ dài bất kỳ thành output có độ dài cố định.
    Được sử dụng để verify data integrity và store passwords securely.
    
    **Tính chất quan trọng:**
    - **Deterministic**: Cùng input luôn cho cùng output
    - **Fixed Output Size**: Output luôn có độ dài cố định
    - **Avalanche Effect**: Thay đổi nhỏ input → thay đổi lớn output
    - **One-way**: Không thể reverse từ hash về plaintext
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 🔤 Hash Generator")
        
        input_text = st.text_area("Input Text:", value="Hello, Cybersecurity!", height=100)
        
        hash_algorithms = ['MD5', 'SHA-1', 'SHA-256', 'SHA-512', 'BLAKE2b']
        selected_algo = st.selectbox("Hash Algorithm:", hash_algorithms)
        
        if st.button("🔄 Generate Hash"):
            hash_result = generate_hash(input_text, selected_algo)
            
            st.markdown("#### 📊 Results:")
            st.text_area("Hash Output:", hash_result['hash'], height=100)
            
            st.info(f"""
            **Algorithm:** {hash_result['algorithm']}
            **Input Length:** {hash_result['input_length']} characters
            **Hash Length:** {hash_result['hash_length']} characters
            **Hex Length:** {len(hash_result['hash'])} characters
            """)
    
    with col2:
        st.markdown("#### 🔍 Hash Comparison")
        
        st.markdown("Thử thay đổi input một chút và xem sự khác biệt:")
        
        input1 = st.text_input("Input 1:", value="Hello World")
        input2 = st.text_input("Input 2:", value="Hello world")  # Chỉ khác chữ hoa/thường
        
        if st.button("🔍 Compare Hashes"):
            hash1 = generate_hash(input1, 'SHA-256')
            hash2 = generate_hash(input2, 'SHA-256')
            
            st.markdown("**Hash 1:**")
            st.code(hash1['hash'])
            
            st.markdown("**Hash 2:**")
            st.code(hash2['hash'])
            
            if hash1['hash'] == hash2['hash']:
                st.success("✅ Hashes are identical!")
            else:
                st.warning("⚠️ Hashes are completely different!")
                
                # Tính toán số bit khác nhau
                diff_bits = calculate_bit_difference(hash1['hash'], hash2['hash'])
                st.info(f"Số bit khác nhau: {diff_bits} / {len(hash1['hash']) * 4}")

def symmetric_encryption_lab():
    """Lab Symmetric Encryption"""
    st.subheader("🔒 Symmetric Encryption Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Symmetric encryption sử dụng cùng một key cho cả encryption và decryption.
    Nhanh và hiệu quả cho việc mã hóa large amounts of data.
    
    **Popular Algorithms:**
    - **AES (Advanced Encryption Standard)**: Hiện tại là standard
    - **DES/3DES**: Cũ, không còn an toàn
    - **ChaCha20**: Modern stream cipher
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 🔒 AES Encryption")
        
        plaintext = st.text_area("Plaintext:", value="This is a secret message!", height=100)
        
        # Key generation options
        key_option = st.radio("Key Option:", ["Generate Random Key", "Use Custom Key"])
        
        if key_option == "Generate Random Key":
            if st.button("🔑 Generate New Key"):
                new_key = Fernet.generate_key()
                st.session_state['aes_key'] = new_key
                st.success("✅ New key generated!")
        else:
            custom_key = st.text_input("Custom Key (Base64):", type="password")
            if custom_key:
                try:
                    st.session_state['aes_key'] = custom_key.encode()
                except:
                    st.error("❌ Invalid key format!")
        
        if 'aes_key' in st.session_state:
            st.info(f"🔑 Current Key: {st.session_state['aes_key'].decode()[:20]}...")
            
            if st.button("🔒 Encrypt"):
                encrypted_result = aes_encrypt(plaintext, st.session_state['aes_key'])
                st.session_state['encrypted_data'] = encrypted_result
                
                st.success("✅ Encryption successful!")
                st.text_area("Encrypted Data:", encrypted_result, height=100)
    
    with col2:
        st.markdown("#### 🔓 AES Decryption")
        
        if 'encrypted_data' in st.session_state and 'aes_key' in st.session_state:
            st.text_area("Encrypted Data:", st.session_state['encrypted_data'], height=100)
            
            if st.button("🔓 Decrypt"):
                try:
                    decrypted_text = aes_decrypt(st.session_state['encrypted_data'], st.session_state['aes_key'])
                    st.success("✅ Decryption successful!")
                    st.text_area("Decrypted Text:", decrypted_text, height=100)
                except Exception as e:
                    st.error(f"❌ Decryption failed: {str(e)}")
        else:
            st.info("👆 Encrypt some data first to see decryption")
        
        st.markdown("#### 🔧 Key Management")
        st.markdown("""
        **Best Practices:**
        - Never hardcode keys in source code
        - Use secure key derivation functions
        - Rotate keys regularly
        - Store keys securely (HSM, Key Vault)
        """)

def asymmetric_encryption_lab():
    """Lab Asymmetric Encryption (RSA)"""
    st.subheader("🔑 Asymmetric Encryption Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Asymmetric encryption sử dụng một cặp key: public key và private key.
    Public key có thể share công khai, private key phải giữ bí mật.
    
    **Use Cases:**
    - **Encryption**: Encrypt với public key, decrypt với private key
    - **Digital Signatures**: Sign với private key, verify với public key
    - **Key Exchange**: Trao đổi symmetric keys an toàn
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 🔑 RSA Key Generation")
        
        key_size = st.selectbox("Key Size:", [1024, 2048, 4096], index=1)
        
        if st.button("🔑 Generate RSA Key Pair"):
            with st.spinner("Generating RSA keys..."):
                keys = generate_rsa_keys(key_size)
                st.session_state['rsa_keys'] = keys
                
                st.success("✅ RSA key pair generated!")
                
                # Hiển thị public key
                st.markdown("**Public Key:**")
                st.text_area("", keys['public_key_pem'], height=150)
        
        if 'rsa_keys' in st.session_state:
            st.markdown("#### 🔒 RSA Encryption")
            
            message = st.text_input("Message to encrypt:", value="Hello RSA!")
            
            if st.button("🔒 Encrypt with Public Key"):
                try:
                    encrypted = rsa_encrypt(message, st.session_state['rsa_keys']['public_key'])
                    st.session_state['rsa_encrypted'] = encrypted
                    
                    st.success("✅ Message encrypted!")
                    st.text_area("Encrypted (Base64):", encrypted, height=100)
                except Exception as e:
                    st.error(f"❌ Encryption failed: {str(e)}")
    
    with col2:
        if 'rsa_keys' in st.session_state:
            st.markdown("#### 🔓 RSA Decryption")
            
            if 'rsa_encrypted' in st.session_state:
                st.text_area("Encrypted Data:", st.session_state['rsa_encrypted'], height=100)
                
                if st.button("🔓 Decrypt with Private Key"):
                    try:
                        decrypted = rsa_decrypt(st.session_state['rsa_encrypted'], st.session_state['rsa_keys']['private_key'])
                        st.success("✅ Message decrypted!")
                        st.write(f"**Decrypted Message:** {decrypted}")
                    except Exception as e:
                        st.error(f"❌ Decryption failed: {str(e)}")
            else:
                st.info("👆 Encrypt a message first")
        
        st.markdown("#### 📊 RSA vs Symmetric Comparison")
        
        comparison_data = {
            "Aspect": ["Speed", "Key Management", "Key Size", "Use Case"],
            "RSA (Asymmetric)": ["Slow", "Easy (public key)", "Large (2048+ bits)", "Key exchange, signatures"],
            "AES (Symmetric)": ["Fast", "Difficult (shared secret)", "Small (256 bits)", "Bulk data encryption"]
        }
        
        import pandas as pd
        df = pd.DataFrame(comparison_data)
        st.dataframe(df, use_container_width=True)

def digital_signatures_lab():
    """Lab Digital Signatures"""
    st.subheader("📝 Digital Signatures Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Digital signatures cung cấp:
    - **Authentication**: Xác thực người gửi
    - **Non-repudiation**: Không thể phủ nhận
    - **Integrity**: Đảm bảo data không bị thay đổi
    
    **Process:**
    1. Hash the message
    2. Encrypt hash with private key (signature)
    3. Send message + signature
    4. Receiver decrypts signature with public key
    5. Compare with hash of received message
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### ✍️ Create Digital Signature")
        
        if 'rsa_keys' not in st.session_state:
            st.warning("⚠️ Generate RSA keys first in the Asymmetric Encryption tab!")
        else:
            message_to_sign = st.text_area("Message to sign:", value="This is an important document.", height=100)
            
            if st.button("✍️ Create Signature"):
                signature = create_digital_signature(message_to_sign, st.session_state['rsa_keys']['private_key'])
                st.session_state['signature'] = signature
                st.session_state['signed_message'] = message_to_sign
                
                st.success("✅ Digital signature created!")
                st.text_area("Signature (Base64):", signature, height=100)
    
    with col2:
        st.markdown("#### ✅ Verify Digital Signature")
        
        if 'signature' in st.session_state and 'signed_message' in st.session_state:
            st.text_area("Original Message:", st.session_state['signed_message'], height=100)
            
            # Cho phép user thay đổi message để test integrity
            test_message = st.text_area("Message to verify:", value=st.session_state['signed_message'], height=100)
            
            if st.button("✅ Verify Signature"):
                is_valid = verify_digital_signature(
                    test_message, 
                    st.session_state['signature'], 
                    st.session_state['rsa_keys']['public_key']
                )
                
                if is_valid:
                    st.success("✅ Signature is VALID! Message is authentic and unmodified.")
                else:
                    st.error("❌ Signature is INVALID! Message may have been tampered with.")
        else:
            st.info("👆 Create a signature first")

def password_security_lab():
    """Lab Password Security"""
    st.subheader("🔐 Password Security Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Password security bao gồm:
    - **Hashing**: Không lưu plaintext passwords
    - **Salting**: Prevent rainbow table attacks
    - **Key Stretching**: Làm chậm brute force attacks
    - **Strong Passwords**: Entropy cao, khó đoán
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 🔐 Password Hashing")
        
        password = st.text_input("Password:", value="MySecurePassword123!", type="password")
        
        hash_method = st.selectbox("Hashing Method:", [
            "PBKDF2 (Recommended)",
            "bcrypt (Good)",
            "Simple SHA-256 (Weak)",
            "MD5 (Very Weak)"
        ])
        
        if st.button("🔄 Hash Password"):
            hash_result = hash_password(password, hash_method)
            
            st.markdown("**Hashed Password:**")
            st.code(hash_result['hash'])
            
            st.info(f"""
            **Method:** {hash_result['method']}
            **Salt:** {hash_result.get('salt', 'None')}
            **Iterations:** {hash_result.get('iterations', 'N/A')}
            **Security Level:** {hash_result['security_level']}
            """)
            
            st.session_state['password_hash'] = hash_result
    
    with col2:
        st.markdown("#### ✅ Password Verification")
        
        if 'password_hash' in st.session_state:
            test_password = st.text_input("Test Password:", type="password")
            
            if st.button("✅ Verify Password"):
                is_valid = verify_password(test_password, st.session_state['password_hash'])
                
                if is_valid:
                    st.success("✅ Password is CORRECT!")
                else:
                    st.error("❌ Password is INCORRECT!")
        
        st.markdown("#### 💪 Password Strength Checker")
        
        check_password = st.text_input("Password to check:", value="password123")
        
        if check_password:
            strength = analyze_password_strength(check_password)
            
            # Hiển thị strength score
            if strength['score'] >= 80:
                st.success(f"💪 Strong Password (Score: {strength['score']}/100)")
            elif strength['score'] >= 60:
                st.warning(f"⚠️ Medium Password (Score: {strength['score']}/100)")
            else:
                st.error(f"❌ Weak Password (Score: {strength['score']}/100)")
            
            # Hiển thị suggestions
            if strength['suggestions']:
                st.markdown("**💡 Suggestions:**")
                for suggestion in strength['suggestions']:
                    st.write(f"• {suggestion}")

# Helper Functions
def generate_hash(text, algorithm):
    """Generate hash using specified algorithm"""
    text_bytes = text.encode('utf-8')
    
    if algorithm == 'MD5':
        hash_obj = hashlib.md5(text_bytes)
        security_level = "Very Weak"
    elif algorithm == 'SHA-1':
        hash_obj = hashlib.sha1(text_bytes)
        security_level = "Weak"
    elif algorithm == 'SHA-256':
        hash_obj = hashlib.sha256(text_bytes)
        security_level = "Strong"
    elif algorithm == 'SHA-512':
        hash_obj = hashlib.sha512(text_bytes)
        security_level = "Very Strong"
    elif algorithm == 'BLAKE2b':
        hash_obj = hashlib.blake2b(text_bytes)
        security_level = "Very Strong"
    
    hash_hex = hash_obj.hexdigest()
    
    return {
        'hash': hash_hex,
        'algorithm': algorithm,
        'input_length': len(text),
        'hash_length': len(hash_hex),
        'security_level': security_level
    }

def calculate_bit_difference(hash1, hash2):
    """Calculate number of different bits between two hashes"""
    if len(hash1) != len(hash2):
        return -1
    
    diff_bits = 0
    for i in range(len(hash1)):
        # Convert hex chars to int and XOR
        xor_result = int(hash1[i], 16) ^ int(hash2[i], 16)
        # Count set bits
        diff_bits += bin(xor_result).count('1')
    
    return diff_bits

def aes_encrypt(plaintext, key):
    """Encrypt text using AES (Fernet)"""
    fernet = Fernet(key)
    encrypted = fernet.encrypt(plaintext.encode())
    return base64.b64encode(encrypted).decode()

def aes_decrypt(encrypted_data, key):
    """Decrypt AES encrypted data"""
    fernet = Fernet(key)
    encrypted_bytes = base64.b64decode(encrypted_data.encode())
    decrypted = fernet.decrypt(encrypted_bytes)
    return decrypted.decode()

def generate_rsa_keys(key_size):
    """Generate RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    
    public_key = private_key.public_key()
    
    # Serialize keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return {
        'private_key': private_key,
        'public_key': public_key,
        'private_key_pem': private_pem.decode(),
        'public_key_pem': public_pem.decode()
    }

def rsa_encrypt(message, public_key):
    """Encrypt message with RSA public key"""
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def rsa_decrypt(encrypted_data, private_key):
    """Decrypt RSA encrypted data"""
    encrypted_bytes = base64.b64decode(encrypted_data.encode())
    decrypted = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def create_digital_signature(message, private_key):
    """Create digital signature"""
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_digital_signature(message, signature, public_key):
    """Verify digital signature"""
    try:
        signature_bytes = base64.b64decode(signature.encode())
        public_key.verify(
            signature_bytes,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

def hash_password(password, method):
    """Hash password using specified method"""
    if method == "PBKDF2 (Recommended)":
        salt = os.urandom(32)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())
        
        return {
            'hash': base64.b64encode(salt + key).decode(),
            'method': 'PBKDF2',
            'salt': base64.b64encode(salt).decode(),
            'iterations': 100000,
            'security_level': 'Very Strong'
        }
    
    elif method == "Simple SHA-256 (Weak)":
        hash_obj = hashlib.sha256(password.encode())
        return {
            'hash': hash_obj.hexdigest(),
            'method': 'SHA-256',
            'security_level': 'Weak (No salt, fast)'
        }
    
    elif method == "MD5 (Very Weak)":
        hash_obj = hashlib.md5(password.encode())
        return {
            'hash': hash_obj.hexdigest(),
            'method': 'MD5',
            'security_level': 'Very Weak (Broken algorithm)'
        }

def verify_password(password, hash_info):
    """Verify password against hash"""
    if hash_info['method'] == 'PBKDF2':
        stored_hash = base64.b64decode(hash_info['hash'].encode())
        salt = stored_hash[:32]
        key = stored_hash[32:]
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=hash_info['iterations'],
        )
        
        try:
            kdf.verify(password.encode(), key)
            return True
        except:
            return False
    
    elif hash_info['method'] == 'SHA-256':
        test_hash = hashlib.sha256(password.encode()).hexdigest()
        return test_hash == hash_info['hash']
    
    elif hash_info['method'] == 'MD5':
        test_hash = hashlib.md5(password.encode()).hexdigest()
        return test_hash == hash_info['hash']
    
    return False

def analyze_password_strength(password):
    """Analyze password strength"""
    score = 0
    suggestions = []
    
    # Length check
    if len(password) >= 12:
        score += 25
    elif len(password) >= 8:
        score += 15
    else:
        suggestions.append("Use at least 8 characters (12+ recommended)")
    
    # Character variety
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    
    char_variety = sum([has_lower, has_upper, has_digit, has_special])
    score += char_variety * 15
    
    if not has_lower:
        suggestions.append("Add lowercase letters")
    if not has_upper:
        suggestions.append("Add uppercase letters")
    if not has_digit:
        suggestions.append("Add numbers")
    if not has_special:
        suggestions.append("Add special characters")
    
    # Common patterns check
    common_patterns = ['123', 'abc', 'password', 'admin', 'qwerty']
    if any(pattern in password.lower() for pattern in common_patterns):
        score -= 20
        suggestions.append("Avoid common patterns and dictionary words")
    
    # Ensure score is between 0 and 100
    score = max(0, min(100, score))
    
    return {
        'score': score,
        'suggestions': suggestions
    }
