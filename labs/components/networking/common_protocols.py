"""
Common Network Protocols - IT Fundamentals Lab
Enhanced with TDD Pattern - Compact UI, Visual Diagrams, Highlighted Keywords
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

def explain_common_protocols():
    """Common Network Protocols - Enhanced with compact TDD pattern"""
    
    # No banner - direct content

    # Protocol Stack Diagram
    st.markdown("#### Internet Protocol Stack")
    
    fig = go.Figure()
    
    # Protocol layers with examples
    layers = [
        {"name": "Application Layer", "y": 4, "color": "#FF6B6B", "protocols": "HTTP, FTP, SMTP, DNS"},
        {"name": "Transport Layer", "y": 3, "color": "#4ECDC4", "protocols": "TCP, UDP"},
        {"name": "Network Layer", "y": 2, "color": "#45B7D1", "protocols": "IP, ICMP, ARP"},
        {"name": "Data Link Layer", "y": 1, "color": "#96CEB4", "protocols": "Ethernet, WiFi"},
        {"name": "Physical Layer", "y": 0, "color": "#A0A0A0", "protocols": "Cables, Radio Waves"}
    ]
    
    for layer in layers:
        fig.add_shape(
            type="rect",
            x0=0, y0=layer["y"]-0.35, x1=10, y1=layer["y"]+0.35,
            fillcolor=layer["color"], opacity=0.7,
            line=dict(color="white", width=2)
        )
        fig.add_annotation(
            x=5, y=layer["y"]+0.1, text=f"<b>{layer['name']}</b>",
            showarrow=False, font=dict(color="white", size=12, family="Arial Black")
        )
        fig.add_annotation(
            x=5, y=layer["y"]-0.15, text=layer['protocols'],
            showarrow=False, font=dict(color="white", size=10)
        )
    
    fig.update_layout(
        title="Internet Protocol Stack with Common Protocols",
        xaxis=dict(visible=False), yaxis=dict(visible=False),
        height=350, showlegend=False,
        margin=dict(l=0, r=0, t=40, b=0)
    )
    
    st.plotly_chart(fig, use_container_width=True)

    # Compact content
    with st.expander("📚 Protocol Fundamentals"):
        st.markdown("""
        <div style="line-height: 1.4;">
        
        ## Core Concepts
        **Definition:** Network protocols are rules and standards that govern communication between devices.
        
        ### Protocol Functions
        **Data Format:** Define how data is structured and encoded  
        **Addressing:** Specify how devices are identified and located  
        **Error Handling:** Manage transmission errors and retransmissions  
        **Flow Control:** Regulate data transmission speed  
        **Security:** Provide authentication and encryption
        
        ### Protocol Categories
        - **Application Protocols:** User-facing services (HTTP, FTP, SMTP)
        - **Transport Protocols:** Reliable data delivery (TCP, UDP)
        - **Network Protocols:** Routing and addressing (IP, ICMP)
        - **Link Protocols:** Local network communication (Ethernet, WiFi)
        
        </div>
        """, unsafe_allow_html=True)

    # Enhanced Protocol Cheat Sheet with Icons
    st.markdown("## 📋 Protocol Cheat Sheet")
    
    tab1, tab2, tab3 = st.tabs(["🌐 Web Protocols", "📧 Email & File Transfer", "🔧 Network Services"])
    
    with tab1:
        st.markdown("### 🌐 Web & Application Protocols")
        
        # Create styled protocol cards
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
                <h4 style="margin: 0 0 0.5rem 0; display: flex; align-items: center;">
                    🌍 HTTP <span style="background: rgba(255,255,255,0.2); padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; margin-left: auto;">Port 80</span>
                </h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Web page transfer (unencrypted)</p>
                <small style="opacity: 0.8;">📝 Example: http://example.com</small>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div style="background: linear-gradient(135deg, #4ecdc4 0%, #44a08d 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
                <h4 style="margin: 0 0 0.5rem 0; display: flex; align-items: center;">
                    🔒 HTTPS <span style="background: rgba(255,255,255,0.2); padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; margin-left: auto;">Port 443</span>
                </h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Secure web transfer (SSL/TLS)</p>
                <small style="opacity: 0.8;">🔐 Example: https://secure-site.com</small>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div style="background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
                <h4 style="margin: 0 0 0.5rem 0; display: flex; align-items: center;">
                    ⚡ WebSocket <span style="background: rgba(255,255,255,0.2); padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; margin-left: auto;">80/443</span>
                </h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Real-time communication</p>
                <small style="opacity: 0.8;">💬 Example: Chat apps, live updates</small>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div style="background: linear-gradient(135deg, #a55eea 0%, #8854d0 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
                <h4 style="margin: 0 0 0.5rem 0; display: flex; align-items: center;">
                    🔗 REST API <span style="background: rgba(255,255,255,0.2); padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; margin-left: auto;">80/443</span>
                </h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Web service communication</p>
                <small style="opacity: 0.8;">📡 Example: GET /api/users</small>
            </div>
            """, unsafe_allow_html=True)

    with tab2:
        st.markdown("### 📧 Email & File Transfer Protocols")
        
        # Email Protocols Section
        st.markdown("#### 📬 Email Protocols")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            <div style="background: linear-gradient(135deg, #fd79a8 0%, #e84393 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
                <h4 style="margin: 0 0 0.5rem 0; display: flex; align-items: center;">
                    📤 SMTP <span style="background: rgba(255,255,255,0.2); padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; margin-left: auto;">25/587</span>
                </h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Send emails (outgoing)</p>
                <small style="opacity: 0.8;">🔒 STARTTLS available</small>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div style="background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
                <h4 style="margin: 0 0 0.5rem 0; display: flex; align-items: center;">
                    📥 POP3 <span style="background: rgba(255,255,255,0.2); padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; margin-left: auto;">110/995</span>
                </h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Retrieve emails (download)</p>
                <small style="opacity: 0.8;">🔐 SSL/TLS on 995</small>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div style="background: linear-gradient(135deg, #55a3ff 0%, #003d82 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
                <h4 style="margin: 0 0 0.5rem 0; display: flex; align-items: center;">
                    📨 IMAP <span style="background: rgba(255,255,255,0.2); padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; margin-left: auto;">143/993</span>
                </h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Manage emails on server</p>
                <small style="opacity: 0.8;">🔐 SSL/TLS on 993</small>
            </div>
            """, unsafe_allow_html=True)
        
        # File Transfer Protocols Section
        st.markdown("#### 📁 File Transfer Protocols")
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            <div style="background: linear-gradient(135deg, #ffeaa7 0%, #fdcb6e 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: #2d3436;">
                <h4 style="margin: 0 0 0.5rem 0; display: flex; align-items: center;">
                    📂 FTP <span style="background: rgba(45,52,54,0.1); padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; margin-left: auto;">Port 21</span>
                </h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.8;">File transfer (unencrypted)</p>
                <small style="opacity: 0.7;">⚠️ Not secure - use SFTP instead</small>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div style="background: linear-gradient(135deg, #00b894 0%, #00a085 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
                <h4 style="margin: 0 0 0.5rem 0; display: flex; align-items: center;">
                    🔐 SFTP <span style="background: rgba(255,255,255,0.2); padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; margin-left: auto;">Port 22</span>
                </h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Secure file transfer (SSH)</p>
                <small style="opacity: 0.8;">✅ Encrypted and secure</small>
            </div>
            """, unsafe_allow_html=True)

    with tab3:
        st.markdown("### 🔧 Network & System Services")
        
        # Core Network Services
        st.markdown("#### 🌐 Core Network Services")
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            <div style="background: linear-gradient(135deg, #6c5ce7 0%, #a29bfe 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
                <h4 style="margin: 0 0 0.5rem 0; display: flex; align-items: center;">
                    🔍 DNS <span style="background: rgba(255,255,255,0.2); padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; margin-left: auto;">Port 53</span>
                </h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Domain name resolution</p>
                <small style="opacity: 0.8;">🌍 google.com → 8.8.8.8</small>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div style="background: linear-gradient(135deg, #fd79a8 0%, #fdcb6e 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
                <h4 style="margin: 0 0 0.5rem 0; display: flex; align-items: center;">
                    🏠 DHCP <span style="background: rgba(255,255,255,0.2); padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; margin-left: auto;">67/68</span>
                </h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Automatic IP assignment</p>
                <small style="opacity: 0.8;">📡 Router assigns IPs to devices</small>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div style="background: linear-gradient(135deg, #00b894 0%, #00cec9 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
                <h4 style="margin: 0 0 0.5rem 0; display: flex; align-items: center;">
                    🔐 SSH <span style="background: rgba(255,255,255,0.2); padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; margin-left: auto;">Port 22</span>
                </h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Secure remote access</p>
                <small style="opacity: 0.8;">💻 ssh user@server.com</small>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div style="background: linear-gradient(135deg, #e17055 0%, #d63031 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
                <h4 style="margin: 0 0 0.5rem 0; display: flex; align-items: center;">
                    ⚠️ Telnet <span style="background: rgba(255,255,255,0.2); padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; margin-left: auto;">Port 23</span>
                </h4>
                <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Remote terminal (insecure)</p>
                <small style="opacity: 0.8;">🚫 Use SSH instead</small>
            </div>
            """, unsafe_allow_html=True)
        
        # Monitoring Services
        st.markdown("#### 📊 Monitoring & Management")
        st.markdown("""
        <div style="background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; color: white;">
            <h4 style="margin: 0 0 0.5rem 0; display: flex; align-items: center;">
                📈 SNMP <span style="background: rgba(255,255,255,0.2); padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; margin-left: auto;">161/162</span>
            </h4>
            <p style="margin: 0; font-size: 0.9rem; opacity: 0.9;">Network monitoring and management</p>
            <small style="opacity: 0.8;">🔧 Monitor router/switch status and performance</small>
        </div>
        """, unsafe_allow_html=True)

    # Interactive Protocol Analyzer
    st.markdown("## 🔧 Protocol Port Checker")
    
    with st.expander("Common Port Reference"):
        col1, col2 = st.columns([2, 1])
        
        with col1:
            port_input = st.number_input(
                "Enter Port Number:", 
                min_value=1, max_value=65535, value=80,
                key="protocol_port_input"
            )
            
            # Common port mappings
            port_mappings = {
                20: "FTP Data", 21: "FTP Control", 22: "SSH/SFTP", 23: "Telnet",
                25: "SMTP", 53: "DNS", 67: "DHCP Server", 68: "DHCP Client",
                80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
                587: "SMTP (Submission)", 993: "IMAPS", 995: "POP3S"
            }
            
        with col2:
            if st.button("Check Protocol", key="protocol_check_port"):
                if port_input in port_mappings:
                    protocol = port_mappings[port_input]
                    st.success(f"✅ Port {port_input}: {protocol}")
                else:
                    st.info(f"ℹ️ Port {port_input}: Not a common protocol port")

    # Protocol Performance Comparison
    st.markdown("## 📊 Protocol Performance Characteristics")
    
    # Create protocol comparison chart
    protocols = ['HTTP/1.1', 'HTTP/2', 'HTTP/3', 'FTP', 'SFTP']
    speed = [60, 85, 95, 70, 65]
    security = [20, 30, 40, 10, 95]
    complexity = [30, 60, 80, 40, 70]
    
    fig = make_subplots(
        rows=1, cols=1,
        specs=[[{"secondary_y": False}]]
    )
    
    fig.add_trace(go.Bar(
        name='Speed',
        x=protocols,
        y=speed,
        marker_color='#4ECDC4',
        yaxis='y'
    ))
    
    fig.add_trace(go.Bar(
        name='Security',
        x=protocols,
        y=security,
        marker_color='#FF6B6B',
        yaxis='y'
    ))
    
    fig.add_trace(go.Bar(
        name='Complexity',
        x=protocols,
        y=complexity,
        marker_color='#96CEB4',
        yaxis='y'
    ))
    
    fig.update_layout(
        title="Protocol Comparison: Speed vs Security vs Complexity",
        xaxis_title="Protocols",
        yaxis_title="Score (0-100)",
        barmode='group',
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)

    # Protocol Security Levels
    st.markdown("## 🔒 Protocol Security Levels")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **🔴 Insecure Protocols:**
        - **HTTP:** Plain text, easily intercepted
        - **FTP:** Credentials sent in clear text
        - **Telnet:** No encryption, deprecated
        - **SMTP (25):** Basic email, no encryption
        
        **🟡 Partially Secure:**
        - **SMTP (587):** Can use STARTTLS
        - **POP3/IMAP:** Basic versions unencrypted
        """)
    
    with col2:
        st.markdown("""
        **🟢 Secure Protocols:**
        - **HTTPS:** SSL/TLS encryption
        - **SFTP:** SSH-based file transfer
        - **SSH:** Encrypted remote access
        - **IMAPS/POP3S:** SSL/TLS email protocols
        
        **🔵 Modern Secure:**
        - **HTTP/3:** QUIC protocol with built-in encryption
        - **TLS 1.3:** Latest encryption standard
        """)

    # Compact Key Takeaways
    st.markdown("""
    <div style="background: #e8f4fd; padding: 1rem; border-radius: 8px; border-left: 4px solid #45b7d1; margin-top: 1rem;">
        <h4 style="margin: 0 0 0.5rem 0; color: #45b7d1; font-size: 1.1rem;">🎯 Key Takeaways</h4>
        <ul style="margin: 0; padding-left: 1.2rem; line-height: 1.4;">
            <li><strong>Protocol Layers:</strong> Application, Transport, Network, Data Link, Physical layers</li>
            <li><strong>Common Ports:</strong> HTTP (80), HTTPS (443), SSH (22), FTP (21), SMTP (25/587)</li>
            <li><strong>Security:</strong> Always prefer encrypted protocols (HTTPS, SFTP, SSH) over plain text</li>
            <li><strong>Email Protocols:</strong> SMTP (send), POP3/IMAP (receive), use secure versions when possible</li>
            <li><strong>Modern Trends:</strong> HTTP/2, HTTP/3, and TLS 1.3 provide better performance and security</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

    # Resources
    st.markdown("## 📚 Learning Resources")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **📖 Protocol References:**
        - [RFC Documents](https://www.rfc-editor.org/) - Official protocol specifications
        - [IANA Port Numbers](https://www.iana.org/assignments/service-names-port-numbers/)
        - [HTTP/2 Explained](https://http2-explained.haxx.se/)
        """)
    
    with col2:
        st.markdown("""
        **🎥 Video Learning:**
        - [Network Protocols Explained](https://www.youtube.com/watch?v=QKfk7YFILws)
        - [HTTP vs HTTPS](https://www.youtube.com/watch?v=hExRDVZHhig)
        - [TCP vs UDP](https://www.youtube.com/watch?v=uwoD5YsGACg)
        """)

if __name__ == "__main__":
    explain_common_protocols()
