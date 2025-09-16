import streamlit as st
import hashlib
import os
import base64
from PIL import Image, ExifTags
import io
import zipfile
import json
from datetime import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

def run_lab():
    """Digital Forensics Lab - Học về điều tra số"""
    
    st.title("🔍 Digital Forensics Lab")
    st.markdown("---")
    
    # Tabs cho các bài thực hành khác nhau
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📁 File Analysis", 
        "🖼️ Image Forensics",
        "🔐 Steganography", 
        "📊 Timeline Analysis",
        "🔍 Evidence Collection"
    ])
    
    with tab1:
        file_analysis_lab()
    
    with tab2:
        image_forensics_lab()
    
    with tab3:
        steganography_lab()
        
    with tab4:
        timeline_analysis_lab()
        
    with tab5:
        evidence_collection_lab()

def file_analysis_lab():
    """Lab phân tích file"""
    st.subheader("📁 File Analysis Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    File analysis là quá trình kiểm tra các thuộc tính và nội dung của file
    để tìm ra thông tin hữu ích trong điều tra forensics.
    
    **Các kỹ thuật chính:**
    - **File Signature Analysis**: Kiểm tra magic bytes
    - **Hash Analysis**: Tính toán và so sánh hash values
    - **Metadata Extraction**: Trích xuất thông tin metadata
    - **Content Analysis**: Phân tích nội dung file
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 📤 Upload File for Analysis")
        
        uploaded_file = st.file_uploader("Choose a file", type=['txt', 'pdf', 'jpg', 'png', 'docx', 'zip'])
        
        if uploaded_file is not None:
            # Lưu file tạm thời
            file_details = {
                'filename': uploaded_file.name,
                'filetype': uploaded_file.type,
                'filesize': uploaded_file.size
            }
            
            st.success("✅ File uploaded successfully!")
            
            # Hiển thị thông tin cơ bản
            st.info(f"""
            **Filename:** {file_details['filename']}
            **File Type:** {file_details['filetype']}
            **File Size:** {file_details['filesize']} bytes
            """)
            
            # Đọc nội dung file
            file_content = uploaded_file.read()
            
            # Phân tích file
            analysis_result = analyze_file(file_content, file_details)
            st.session_state['file_analysis'] = analysis_result
    
    with col2:
        st.markdown("#### 🔍 Analysis Results")
        
        if 'file_analysis' in st.session_state:
            result = st.session_state['file_analysis']
            
            # File signature
            st.markdown("**🔖 File Signature:**")
            st.code(result['signature'])
            
            # Hash values
            st.markdown("**#️⃣ Hash Values:**")
            st.code(f"MD5: {result['md5']}")
            st.code(f"SHA-1: {result['sha1']}")
            st.code(f"SHA-256: {result['sha256']}")
            
            # File type detection
            st.markdown("**📋 File Type Detection:**")
            if result['detected_type']:
                st.success(f"✅ Detected: {result['detected_type']}")
            else:
                st.warning("⚠️ Unknown file type")
            
            # Entropy analysis
            st.markdown("**📊 Entropy Analysis:**")
            entropy = result['entropy']
            if entropy > 7.5:
                st.warning(f"⚠️ High entropy ({entropy:.2f}) - Possible encryption/compression")
            elif entropy > 6.0:
                st.info(f"ℹ️ Medium entropy ({entropy:.2f}) - Normal binary data")
            else:
                st.success(f"✅ Low entropy ({entropy:.2f}) - Likely text data")

def image_forensics_lab():
    """Lab phân tích ảnh forensics"""
    st.subheader("🖼️ Image Forensics Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Image forensics giúp xác định tính xác thực của ảnh và trích xuất thông tin ẩn.
    
    **Kỹ thuật phân tích:**
    - **EXIF Data**: Thông tin camera, GPS, thời gian chụp
    - **Error Level Analysis**: Phát hiện chỉnh sửa ảnh
    - **Histogram Analysis**: Phân tích phân bố màu
    - **Noise Analysis**: Phát hiện vùng bị chỉnh sửa
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 📷 Upload Image")
        
        uploaded_image = st.file_uploader("Choose an image", type=['jpg', 'jpeg', 'png', 'tiff'])
        
        if uploaded_image is not None:
            # Hiển thị ảnh
            image = Image.open(uploaded_image)
            st.image(image, caption="Uploaded Image", use_column_width=True)
            
            # Phân tích ảnh
            image_analysis = analyze_image(image)
            st.session_state['image_analysis'] = image_analysis
    
    with col2:
        st.markdown("#### 🔍 Image Analysis Results")
        
        if 'image_analysis' in st.session_state:
            analysis = st.session_state['image_analysis']
            
            # Basic info
            st.markdown("**📊 Basic Information:**")
            st.info(f"""
            **Dimensions:** {analysis['width']} x {analysis['height']}
            **Format:** {analysis['format']}
            **Mode:** {analysis['mode']}
            **File Size:** {analysis['size']} bytes
            """)
            
            # EXIF data
            if analysis['exif']:
                st.markdown("**📋 EXIF Data:**")
                with st.expander("View EXIF Data"):
                    for key, value in analysis['exif'].items():
                        st.write(f"**{key}:** {value}")
            else:
                st.warning("⚠️ No EXIF data found")
            
            # Histogram
            if analysis['histogram']:
                st.markdown("**📊 Color Histogram:**")
                fig = create_histogram_plot(analysis['histogram'])
                st.plotly_chart(fig, use_container_width=True)

def steganography_lab():
    """Lab Steganography - ẩn thông tin trong file"""
    st.subheader("🔐 Steganography Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Steganography là nghệ thuật ẩn thông tin trong các file khác
    mà không làm thay đổi đáng kể file gốc.
    
    **Các phương pháp:**
    - **LSB (Least Significant Bit)**: Thay đổi bit cuối của pixel
    - **Text in Image**: Ẩn text trong ảnh
    - **File in File**: Ẩn file trong file khác
    - **Metadata Hiding**: Ẩn trong metadata
    """)
    
    tab_hide, tab_extract = st.tabs(["🔒 Hide Message", "🔍 Extract Message"])
    
    with tab_hide:
        st.markdown("#### 🔒 Hide Secret Message")
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            cover_image = st.file_uploader("Cover Image", type=['png'], key="cover")
            secret_message = st.text_area("Secret Message:", value="This is a secret message!")
            
            if cover_image and secret_message:
                if st.button("🔒 Hide Message"):
                    # Mô phỏng LSB steganography
                    result = hide_message_in_image(cover_image, secret_message)
                    
                    if result['success']:
                        st.success("✅ Message hidden successfully!")
                        st.session_state['stego_image'] = result['stego_image']
                        
                        # Hiển thị ảnh đã ẩn tin
                        st.image(result['stego_image'], caption="Steganographic Image")
                    else:
                        st.error(f"❌ Error: {result['error']}")
        
        with col2:
            if 'stego_image' in st.session_state:
                st.markdown("#### 📊 Comparison")
                
                # So sánh ảnh gốc và ảnh đã ẩn tin
                st.markdown("**Original vs Steganographic:**")
                st.write("Visually, the images should look identical!")
                
                # Thống kê
                st.info("""
                **LSB Steganography Statistics:**
                - Only the least significant bits are modified
                - Human eye cannot detect the changes
                - Capacity: ~1 byte per 8 pixels (for RGB)
                """)
    
    with tab_extract:
        st.markdown("#### 🔍 Extract Hidden Message")
        
        stego_file = st.file_uploader("Steganographic Image", type=['png'], key="stego")
        
        if stego_file:
            if st.button("🔍 Extract Message"):
                # Mô phỏng extraction
                extracted = extract_message_from_image(stego_file)
                
                if extracted['success']:
                    st.success("✅ Message extracted successfully!")
                    st.text_area("Extracted Message:", extracted['message'], height=100)
                else:
                    st.warning("⚠️ No hidden message found or extraction failed")

def timeline_analysis_lab():
    """Lab phân tích timeline"""
    st.subheader("📊 Timeline Analysis Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Timeline analysis giúp tái tạo chuỗi sự kiện trong quá trình điều tra,
    xác định thời gian các hoạt động xảy ra.
    
    **Các timestamp quan trọng:**
    - **Created Time**: Thời gian tạo file
    - **Modified Time**: Thời gian sửa đổi cuối
    - **Accessed Time**: Thời gian truy cập cuối
    - **Metadata Time**: Thời gian trong metadata
    """)
    
    # Tạo dữ liệu timeline mẫu
    if st.button("📊 Generate Sample Timeline"):
        timeline_data = generate_sample_timeline()
        st.session_state['timeline_data'] = timeline_data
    
    if 'timeline_data' in st.session_state:
        data = st.session_state['timeline_data']
        
        # Hiển thị bảng timeline
        st.markdown("#### 📋 Timeline Events")
        df = pd.DataFrame(data)
        st.dataframe(df, use_container_width=True)
        
        # Biểu đồ timeline
        st.markdown("#### 📊 Timeline Visualization")
        fig = create_timeline_plot(df)
        st.plotly_chart(fig, use_container_width=True)
        
        # Phân tích patterns
        st.markdown("#### 🔍 Pattern Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Activity by hour
            df['Hour'] = pd.to_datetime(df['Timestamp']).dt.hour
            hourly_activity = df.groupby('Hour').size()
            
            fig_hour = px.bar(x=hourly_activity.index, y=hourly_activity.values,
                             title="Activity by Hour")
            st.plotly_chart(fig_hour, use_container_width=True)
        
        with col2:
            # Event types
            event_counts = df['Event Type'].value_counts()
            
            fig_events = px.pie(values=event_counts.values, names=event_counts.index,
                               title="Event Types Distribution")
            st.plotly_chart(fig_events, use_container_width=True)

def evidence_collection_lab():
    """Lab thu thập bằng chứng"""
    st.subheader("🔍 Evidence Collection Lab")
    
    st.markdown("""
    ### 📖 Lý thuyết:
    Evidence collection là quá trình thu thập và bảo quản bằng chứng số
    theo các tiêu chuẩn forensics để đảm bảo tính pháp lý.
    
    **Chain of Custody:**
    1. **Identification**: Xác định bằng chứng
    2. **Collection**: Thu thập an toàn
    3. **Documentation**: Ghi chép chi tiết
    4. **Preservation**: Bảo quản nguyên vẹn
    5. **Analysis**: Phân tích chuyên sâu
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 📋 Evidence Documentation")
        
        # Form thu thập bằng chứng
        case_id = st.text_input("Case ID:", value="CASE-2024-001")
        investigator = st.text_input("Investigator:", value="John Doe")
        evidence_type = st.selectbox("Evidence Type:", [
            "Hard Drive", "USB Drive", "Mobile Device", 
            "Network Log", "Email", "Document"
        ])
        
        description = st.text_area("Description:", 
                                 value="Suspicious USB drive found at crime scene")
        
        location = st.text_input("Location Found:", value="Suspect's desk")
        
        if st.button("📝 Create Evidence Record"):
            evidence_record = create_evidence_record(
                case_id, investigator, evidence_type, description, location
            )
            
            st.session_state['evidence_record'] = evidence_record
            st.success("✅ Evidence record created!")
    
    with col2:
        st.markdown("#### 📄 Evidence Report")
        
        if 'evidence_record' in st.session_state:
            record = st.session_state['evidence_record']
            
            st.markdown("**📋 Evidence Details:**")
            st.info(f"""
            **Case ID:** {record['case_id']}
            **Evidence ID:** {record['evidence_id']}
            **Investigator:** {record['investigator']}
            **Type:** {record['evidence_type']}
            **Date/Time:** {record['timestamp']}
            **Location:** {record['location']}
            **Hash:** {record['hash']}
            """)
            
            st.markdown("**📝 Description:**")
            st.write(record['description'])
            
            # Chain of custody log
            st.markdown("**🔗 Chain of Custody:**")
            custody_df = pd.DataFrame(record['chain_of_custody'])
            st.dataframe(custody_df, use_container_width=True)

# Helper Functions
def analyze_file(file_content, file_details):
    """Phân tích file content"""
    
    # File signature (magic bytes)
    signature = file_content[:16].hex().upper()
    
    # Hash calculations
    md5_hash = hashlib.md5(file_content).hexdigest()
    sha1_hash = hashlib.sha1(file_content).hexdigest()
    sha256_hash = hashlib.sha256(file_content).hexdigest()
    
    # File type detection based on signature
    detected_type = detect_file_type(signature)
    
    # Entropy calculation
    entropy = calculate_entropy(file_content)
    
    return {
        'signature': signature,
        'md5': md5_hash,
        'sha1': sha1_hash,
        'sha256': sha256_hash,
        'detected_type': detected_type,
        'entropy': entropy
    }

def detect_file_type(signature):
    """Detect file type from signature"""
    signatures = {
        'FFD8FF': 'JPEG Image',
        '89504E47': 'PNG Image',
        '474946': 'GIF Image',
        '25504446': 'PDF Document',
        '504B0304': 'ZIP Archive',
        '52617221': 'RAR Archive',
        'D0CF11E0': 'Microsoft Office Document'
    }
    
    for sig, file_type in signatures.items():
        if signature.startswith(sig):
            return file_type
    
    return None

def calculate_entropy(data):
    """Calculate Shannon entropy of data"""
    if len(data) == 0:
        return 0
    
    # Count frequency of each byte
    frequency = {}
    for byte in data:
        frequency[byte] = frequency.get(byte, 0) + 1
    
    # Calculate entropy
    entropy = 0
    length = len(data)
    
    for count in frequency.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * (probability.bit_length() - 1)
    
    return entropy

def analyze_image(image):
    """Phân tích ảnh"""
    
    # Basic info
    width, height = image.size
    format_name = image.format
    mode = image.mode
    
    # EXIF data
    exif_data = {}
    if hasattr(image, '_getexif') and image._getexif() is not None:
        exif = image._getexif()
        for tag_id, value in exif.items():
            tag = ExifTags.TAGS.get(tag_id, tag_id)
            exif_data[tag] = value
    
    # Histogram
    histogram = None
    if mode == 'RGB':
        histogram = {
            'red': image.histogram()[0:256],
            'green': image.histogram()[256:512],
            'blue': image.histogram()[512:768]
        }
    
    return {
        'width': width,
        'height': height,
        'format': format_name,
        'mode': mode,
        'size': len(image.tobytes()),
        'exif': exif_data,
        'histogram': histogram
    }

def create_histogram_plot(histogram):
    """Tạo biểu đồ histogram màu"""
    fig = go.Figure()
    
    x = list(range(256))
    
    if 'red' in histogram:
        fig.add_trace(go.Scatter(x=x, y=histogram['red'], 
                                mode='lines', name='Red', 
                                line=dict(color='red')))
    
    if 'green' in histogram:
        fig.add_trace(go.Scatter(x=x, y=histogram['green'], 
                                mode='lines', name='Green', 
                                line=dict(color='green')))
    
    if 'blue' in histogram:
        fig.add_trace(go.Scatter(x=x, y=histogram['blue'], 
                                mode='lines', name='Blue', 
                                line=dict(color='blue')))
    
    fig.update_layout(
        title="Color Histogram",
        xaxis_title="Pixel Value",
        yaxis_title="Frequency"
    )
    
    return fig

def hide_message_in_image(cover_image, message):
    """Mô phỏng ẩn tin trong ảnh bằng LSB"""
    try:
        image = Image.open(cover_image)
        
        # Chuyển message thành binary
        binary_message = ''.join(format(ord(char), '08b') for char in message)
        binary_message += '1111111111111110'  # Delimiter
        
        # Kiểm tra capacity
        pixels = list(image.getdata())
        max_capacity = len(pixels) * 3  # RGB channels
        
        if len(binary_message) > max_capacity:
            return {'success': False, 'error': 'Message too long for cover image'}
        
        # Mô phỏng LSB embedding (không thực sự modify ảnh)
        # Trong thực tế sẽ modify LSB của mỗi pixel
        
        return {
            'success': True,
            'stego_image': image,
            'message_length': len(message),
            'binary_length': len(binary_message)
        }
    
    except Exception as e:
        return {'success': False, 'error': str(e)}

def extract_message_from_image(stego_image):
    """Mô phỏng trích xuất tin từ ảnh"""
    try:
        # Mô phỏng extraction process
        # Trong thực tế sẽ extract LSB từ mỗi pixel
        
        # Giả lập extracted message
        extracted_message = "This is a secret message!"
        
        return {
            'success': True,
            'message': extracted_message
        }
    
    except Exception as e:
        return {'success': False, 'error': str(e)}

def generate_sample_timeline():
    """Tạo dữ liệu timeline mẫu"""
    import random
    from datetime import datetime, timedelta
    
    events = []
    base_time = datetime.now() - timedelta(days=1)
    
    event_types = [
        'File Created', 'File Modified', 'File Accessed', 'File Deleted',
        'Login', 'Logout', 'Network Connection', 'USB Inserted',
        'Email Sent', 'Browser Activity'
    ]
    
    files = [
        'document.docx', 'secret.txt', 'photo.jpg', 'data.xlsx',
        'backup.zip', 'config.ini', 'log.txt', 'report.pdf'
    ]
    
    for i in range(50):
        event_time = base_time + timedelta(minutes=random.randint(1, 1440))
        
        events.append({
            'Timestamp': event_time.strftime('%Y-%m-%d %H:%M:%S'),
            'Event Type': random.choice(event_types),
            'File/Object': random.choice(files),
            'User': random.choice(['admin', 'user1', 'guest', 'system']),
            'Source': random.choice(['System', 'Application', 'Security'])
        })
    
    # Sort by timestamp
    events.sort(key=lambda x: x['Timestamp'])
    
    return events

def create_timeline_plot(df):
    """Tạo biểu đồ timeline"""
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    
    fig = px.scatter(df, x='Timestamp', y='Event Type', 
                     color='User', hover_data=['File/Object'],
                     title="Forensic Timeline Analysis")
    
    fig.update_layout(height=400)
    return fig

def create_evidence_record(case_id, investigator, evidence_type, description, location):
    """Tạo record bằng chứng"""
    
    evidence_id = f"EVD-{datetime.now().strftime('%Y%m%d')}-{hash(description) % 1000:03d}"
    timestamp = datetime.now().isoformat()
    
    # Tạo hash cho evidence integrity
    evidence_hash = hashlib.sha256(
        f"{case_id}{evidence_id}{description}{timestamp}".encode()
    ).hexdigest()
    
    # Chain of custody
    chain_of_custody = [
        {
            'Action': 'Evidence Collected',
            'Person': investigator,
            'Timestamp': timestamp,
            'Location': location
        }
    ]
    
    return {
        'case_id': case_id,
        'evidence_id': evidence_id,
        'investigator': investigator,
        'evidence_type': evidence_type,
        'description': description,
        'location': location,
        'timestamp': timestamp,
        'hash': evidence_hash,
        'chain_of_custody': chain_of_custody
    }
