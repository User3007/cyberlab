#!/bin/bash

# Cybersecurity Lab Setup Script for Ubuntu VM
# This script installs all necessary dependencies and tools

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root. Please run as a regular user."
        exit 1
    fi
}

# Check Ubuntu version
check_ubuntu_version() {
    if ! lsb_release -d | grep -q "Ubuntu"; then
        error "This script is designed for Ubuntu. Current OS: $(lsb_release -d)"
        exit 1
    fi
    
    UBUNTU_VERSION=$(lsb_release -rs)
    info "Detected Ubuntu version: $UBUNTU_VERSION"
    
    # Check if version is supported (18.04+)
    if [[ $(echo "$UBUNTU_VERSION >= 18.04" | bc -l) -eq 0 ]]; then
        warn "Ubuntu version $UBUNTU_VERSION may not be fully supported. Recommended: 20.04+"
    fi
}

# Update system packages
update_system() {
    log "Updating system packages..."
    sudo apt update
    sudo apt upgrade -y
    
    log "Installing essential packages..."
    sudo apt install -y \
        curl \
        wget \
        git \
        vim \
        htop \
        tree \
        unzip \
        build-essential \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release \
        bc
}

# Install Python and pip
install_python() {
    log "Installing Python and pip..."
    
    # Install Python 3.9+ if not available
    PYTHON_VERSION=$(python3 --version 2>/dev/null | cut -d' ' -f2 | cut -d'.' -f1-2 || echo "0.0")
    
    if [[ $(echo "$PYTHON_VERSION >= 3.8" | bc -l) -eq 0 ]]; then
        log "Installing Python 3.9..."
        sudo apt install -y python3.9 python3.9-dev python3.9-venv
        sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.9 1
    else
        log "Python $PYTHON_VERSION is already installed"
        sudo apt install -y python3-dev python3-venv
    fi
    
    # Install pip
    sudo apt install -y python3-pip
    
    # Upgrade pip
    python3 -m pip install --upgrade pip
}

# Install security tools
install_security_tools() {
    log "Installing security tools..."
    
    # Network tools
    sudo apt install -y \
        nmap \
        netcat \
        tcpdump \
        wireshark \
        aircrack-ng \
        hashcat \
        john \
        hydra \
        nikto \
        sqlmap \
        gobuster \
        dirb
    
    # Add user to wireshark group
    sudo usermod -a -G wireshark $USER
    
    # Forensics tools
    sudo apt install -y \
        binwalk \
        foremost \
        exiftool \
        steghide \
        outguess \
        stegosuite
    
    # Install additional tools via snap (if available)
    if command -v snap &> /dev/null; then
        log "Installing additional tools via snap..."
        sudo snap install code --classic || warn "Failed to install VS Code via snap"
    fi
}

# Create Python virtual environment
create_venv() {
    log "Creating Python virtual environment..."
    
    cd /home/$USER
    
    if [ ! -d "cybersecurity-lab" ]; then
        error "cybersecurity-lab directory not found. Please ensure the lab files are in the correct location."
        exit 1
    fi
    
    cd cybersecurity-lab
    
    # Create virtual environment
    python3 -m venv venv
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip in venv
    pip install --upgrade pip
    
    log "Installing Python packages..."
    pip install -r requirements.txt
    
    deactivate
}

# Install Docker (optional)
install_docker() {
    read -p "Do you want to install Docker? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log "Installing Docker..."
        
        # Remove old versions
        sudo apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
        
        # Add Docker's official GPG key
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        
        # Add Docker repository
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        # Install Docker
        sudo apt update
        sudo apt install -y docker-ce docker-ce-cli containerd.io
        
        # Add user to docker group
        sudo usermod -aG docker $USER
        
        # Start and enable Docker
        sudo systemctl start docker
        sudo systemctl enable docker
        
        log "Docker installed successfully!"
    else
        info "Skipping Docker installation"
    fi
}

# Configure firewall
configure_firewall() {
    log "Configuring firewall..."
    
    # Enable UFW
    sudo ufw --force enable
    
    # Allow SSH
    sudo ufw allow ssh
    
    # Allow Streamlit default port
    sudo ufw allow 8501
    
    # Allow common web ports for testing
    sudo ufw allow 80
    sudo ufw allow 443
    
    log "Firewall configured"
}

# Create desktop shortcuts
create_shortcuts() {
    log "Creating desktop shortcuts..."
    
    DESKTOP_DIR="/home/$USER/Desktop"
    mkdir -p "$DESKTOP_DIR"
    
    # Cybersecurity Lab shortcut
    cat > "$DESKTOP_DIR/Cybersecurity-Lab.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Cybersecurity Lab
Comment=Launch Cybersecurity Learning Environment
Exec=gnome-terminal -- bash -c 'cd /home/$USER/cybersecurity-lab && source venv/bin/activate && streamlit run main.py'
Icon=applications-security
Terminal=false
Categories=Education;Security;
EOF
    
    chmod +x "$DESKTOP_DIR/Cybersecurity-Lab.desktop"
    
    # Terminal shortcut
    cat > "$DESKTOP_DIR/Lab-Terminal.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Lab Terminal
Comment=Terminal with lab environment activated
Exec=gnome-terminal -- bash -c 'cd /home/$USER/cybersecurity-lab && source venv/bin/activate && bash'
Icon=utilities-terminal
Terminal=false
Categories=System;
EOF
    
    chmod +x "$DESKTOP_DIR/Lab-Terminal.desktop"
}

# Create startup script
create_startup_script() {
    log "Creating startup script..."
    
    cat > "/home/$USER/cybersecurity-lab/start_lab.sh" << 'EOF'
#!/bin/bash

# Cybersecurity Lab Startup Script

cd "$(dirname "$0")"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Please run setup.sh first."
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Check if all packages are installed
python -c "import streamlit, pandas, numpy, matplotlib, seaborn, plotly, requests, beautifulsoup4, scapy, cryptography" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Some packages are missing. Installing..."
    pip install -r requirements.txt
fi

# Start Streamlit app
echo "Starting Cybersecurity Lab..."
echo "Open your browser and go to: http://localhost:8501"
echo "Press Ctrl+C to stop the lab"

streamlit run main.py --server.address 0.0.0.0 --server.port 8501
EOF
    
    chmod +x "/home/$USER/cybersecurity-lab/start_lab.sh"
}

# Set up aliases
setup_aliases() {
    log "Setting up aliases..."
    
    # Add aliases to .bashrc
    cat >> "/home/$USER/.bashrc" << 'EOF'

# Cybersecurity Lab Aliases
alias lab='cd ~/cybersecurity-lab && source venv/bin/activate'
alias start-lab='cd ~/cybersecurity-lab && ./start_lab.sh'
alias lab-update='cd ~/cybersecurity-lab && source venv/bin/activate && pip install --upgrade -r requirements.txt'

EOF
    
    log "Aliases added to .bashrc"
}

# Install additional browsers for web security testing
install_browsers() {
    log "Installing additional browsers..."
    
    # Firefox (usually pre-installed)
    sudo apt install -y firefox
    
    # Chromium
    sudo apt install -y chromium-browser
    
    # Install Tor Browser (optional)
    read -p "Do you want to install Tor Browser? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log "Installing Tor Browser..."
        
        # Add Tor repository
        wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --dearmor | sudo tee /usr/share/keyrings/tor-archive-keyring.gpg >/dev/null
        echo "deb [arch=amd64 signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/tor.list
        
        sudo apt update
        sudo apt install -y tor torbrowser-launcher
    fi
}

# Final system configuration
final_configuration() {
    log "Performing final configuration..."
    
    # Update locate database
    sudo updatedb 2>/dev/null || true
    
    # Set up log rotation for lab logs
    sudo tee /etc/logrotate.d/cybersecurity-lab > /dev/null << EOF
/home/$USER/cybersecurity-lab/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF
    
    # Create logs directory
    mkdir -p "/home/$USER/cybersecurity-lab/logs"
    
    # Set proper permissions
    chmod 755 "/home/$USER/cybersecurity-lab"
    chmod +x "/home/$USER/cybersecurity-lab/main.py"
}

# Print completion message
print_completion() {
    echo
    echo "=================================================================="
    echo -e "${GREEN}🎉 Cybersecurity Lab Setup Complete! 🎉${NC}"
    echo "=================================================================="
    echo
    echo -e "${BLUE}📋 What's been installed:${NC}"
    echo "  ✅ Python 3.9+ with virtual environment"
    echo "  ✅ Streamlit and all required Python packages"
    echo "  ✅ Security tools (nmap, wireshark, hashcat, etc.)"
    echo "  ✅ Forensics tools (binwalk, exiftool, steghide, etc.)"
    echo "  ✅ Desktop shortcuts and aliases"
    echo "  ✅ Firewall configuration"
    echo
    echo -e "${YELLOW}🚀 How to start the lab:${NC}"
    echo "  1. Reboot your system (recommended)"
    echo "  2. Double-click 'Cybersecurity Lab' on desktop, OR"
    echo "  3. Open terminal and run: start-lab"
    echo "  4. Open browser and go to: http://localhost:8501"
    echo
    echo -e "${BLUE}📚 Useful commands:${NC}"
    echo "  lab          - Navigate to lab directory and activate environment"
    echo "  start-lab    - Start the Streamlit application"
    echo "  lab-update   - Update Python packages"
    echo
    echo -e "${YELLOW}⚠️  Important Notes:${NC}"
    echo "  • Some tools may require a system reboot to work properly"
    echo "  • Wireshark requires logout/login to use without sudo"
    echo "  • Docker (if installed) requires logout/login for group membership"
    echo
    echo -e "${GREEN}Happy learning! 🔒🎓${NC}"
    echo "=================================================================="
}

# Main execution
main() {
    log "Starting Cybersecurity Lab setup..."
    
    check_root
    check_ubuntu_version
    update_system
    install_python
    install_security_tools
    create_venv
    install_docker
    configure_firewall
    create_shortcuts
    create_startup_script
    setup_aliases
    install_browsers
    final_configuration
    print_completion
}

# Run main function
main "$@"
