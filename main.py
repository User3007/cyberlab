import streamlit as st
import os
import sys

# Thêm thư mục labs vào Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'labs'))

# Import các lab modules
from labs import network_security, web_security, cryptography_lab, digital_forensics, advanced_networking, wireless_security, theory_concepts, it_fundamentals, software_development

def main():
    st.set_page_config(
        page_title="Cybersecurity Learning Lab",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # CSS tùy chỉnh - Ultra compact
    st.markdown("""
    <style>
    .main-header {
        font-size: 1.8rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 0.5rem;
    }
    .lab-card {
        background-color: #f0f2f6;
        padding: 0.5rem;
        border-radius: 6px;
        margin: 0.5rem 0;
        border-left: 3px solid #1f77b4;
    }
    .sidebar .sidebar-content {
        background-color: #262730;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Header - Ultra compact
    st.markdown('<h1 class="main-header">🔒 Cybersecurity Learning Lab</h1>', unsafe_allow_html=True)
    
    # Sidebar navigation
    st.sidebar.title("🎯 Chọn Lab")
    st.sidebar.markdown("Chọn một lab để bắt đầu học:")
    
    lab_choice = st.sidebar.selectbox(
        "Danh sách Labs:",
        [
            "🏠 Trang chủ",
            "📚 Theory & Concepts",
            "💻 IT Fundamentals",
            "💾 Software Development",
            "🌐 Network Security",
            "🌍 Advanced Networking",
            "📡 Wireless Security",
            "🕸️ Web Security", 
            "🔐 Cryptography",
            "🔍 Digital Forensics"
        ]
    )
    
    # Main content area
    if lab_choice == "🏠 Trang chủ":
        show_home_page()
    elif lab_choice == "📚 Theory & Concepts":
        theory_concepts.run_lab()
    elif lab_choice == "💻 IT Fundamentals":
        it_fundamentals.run_lab()
    elif lab_choice == "💾 Software Development":
        software_development.run_lab()
    elif lab_choice == "🌐 Network Security":
        network_security.run_lab()
    elif lab_choice == "🌍 Advanced Networking":
        advanced_networking.run_lab()
    elif lab_choice == "📡 Wireless Security":
        wireless_security.run_lab()
    elif lab_choice == "🕸️ Web Security":
        web_security.run_lab()
    elif lab_choice == "🔐 Cryptography":
        cryptography_lab.run_lab()
    elif lab_choice == "🔍 Digital Forensics":
        digital_forensics.run_lab()

def show_home_page():
    """Hiển thị trang chủ với thông tin tổng quan"""
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("""
        ## 🎓 Chào mừng đến với Cybersecurity Learning Lab!
        
        Đây là môi trường học tập tương tác được thiết kế đặc biệt cho sinh viên mới bắt đầu học về An toàn thông tin.
        
        ### 🚀 Các tính năng chính:
        - **Giao diện thân thiện**: Sử dụng Streamlit để tạo trải nghiệm học tập trực quan
        - **Thực hành thực tế**: Các lab mô phỏng tình huống thực tế trong cybersecurity
        - **Học từng bước**: Hướng dẫn chi tiết từ cơ bản đến nâng cao
        - **An toàn**: Môi trường sandbox an toàn để thực hành
        """)
        
        st.markdown("### 📚 Danh sách Labs có sẵn:")
        
        labs_info = [
            {
                "name": "📚 Theory & Concepts",
                "description": "Học các khái niệm cơ bản và thủ thuật cybersecurity",
                "tools": "OSI Model, CIA Triad, Attack methodologies, Risk assessment"
            },
            {
                "name": "💻 IT Fundamentals",
                "description": "Kiến thức nền tảng CNTT: Computer systems, OS, Database",
                "tools": "Computer architecture, Networking basics, System administration"
            },
            {
                "name": "💾 Software Development",
                "description": "Phát triển phần mềm: SDLC, Programming, Testing, DevOps",
                "tools": "Agile/Scrum, OOP, Data structures, CI/CD, Project management"
            },
            {
                "name": "🌐 Network Security",
                "description": "Học về bảo mật mạng cơ bản, quét port, phân tích gói tin",
                "tools": "Nmap, Scapy, Wireshark simulation"
            },
            {
                "name": "🌍 Advanced Networking",
                "description": "Networking nâng cao, topology mapping, performance analysis",
                "tools": "Network reconnaissance, Protocol analysis, Traffic monitoring"
            },
            {
                "name": "📡 Wireless Security",
                "description": "Bảo mật mạng không dây, WiFi analysis, rogue AP detection",
                "tools": "WiFi scanning, WPA/WEP analysis, Signal monitoring"
            },
            {
                "name": "🕸️ Web Security", 
                "description": "Tìm hiểu về các lỗ hổng web phổ biến",
                "tools": "SQL Injection, XSS, CSRF simulation"
            },
            {
                "name": "🔐 Cryptography",
                "description": "Thực hành mã hóa và giải mã",
                "tools": "AES, RSA, Hash functions, Digital signatures"
            },
            {
                "name": "🔍 Digital Forensics",
                "description": "Phân tích bằng chứng số và điều tra",
                "tools": "File analysis, Metadata extraction, Steganography"
            }
        ]
        
        for lab in labs_info:
            with st.expander(f"**{lab['name']}**"):
                st.write(f"**Mô tả:** {lab['description']}")
                st.write(f"**Công cụ:** {lab['tools']}")
    
    with col2:
        st.markdown("### 📊 Thống kê hệ thống")
        
        # Hiển thị thông tin hệ thống
        import platform
        import psutil
        
        st.info(f"""
        **Hệ điều hành:** {platform.system()} {platform.release()}
        
        **Python:** {platform.python_version()}
        
        **CPU:** {psutil.cpu_count()} cores
        
        **RAM:** {psutil.virtual_memory().total // (1024**3)} GB
        """)
        
        st.markdown("### 🔧 Hướng dẫn sử dụng")
        st.markdown("""
        1. Chọn lab từ sidebar bên trái
        2. Đọc kỹ hướng dẫn trước khi thực hành
        3. Làm theo từng bước được hướng dẫn
        4. Thử nghiệm với các tham số khác nhau
        5. Ghi chú lại những gì học được
        """)

if __name__ == "__main__":
    main()
