# 🔬 DANH SÁCH LAB THỰC HÀNH CHI TIẾT THEO LỘ TRÌNH

## 📋 HƯỚNG DẪN SỬ DỤNG LABS

### Cấu trúc mỗi Lab
- **Objective**: Mục tiêu cần đạt
- **Duration**: Thời gian dự kiến
- **Prerequisites**: Kiến thức cần có
- **Tools Required**: Công cụ cần thiết
- **Difficulty**: Easy/Medium/Hard/Expert
- **Real-world Application**: Ứng dụng thực tế

---

## 🎯 PHASE 1: FOUNDATION LABS (Tháng 1-3)

### 🖥️ Week 1-2: Linux Fundamentals Labs

#### Lab 1.1: Linux Command Line Mastery
- **Duration**: 4 hours
- **Difficulty**: Easy
- **Objectives**:
  - Navigate filesystem efficiently
  - File permissions và ownership
  - Process management
  - Package management
- **Exercises**:
  1. Create complex directory structure using single command
  2. Find all SUID binaries on system
  3. Monitor real-time process với specific filters
  4. Create bash aliases cho common tasks
- **Challenge**: Write script to automate system hardening

#### Lab 1.2: Linux Privilege Escalation
- **Duration**: 6 hours
- **Difficulty**: Medium
- **Objectives**:
  - Enumerate system for privesc vectors
  - Exploit misconfigurations
  - Understand SUID/GUID
- **Exercises**:
  1. Use LinPEAS/LinEnum for enumeration
  2. Exploit cron job misconfigurations
  3. Abuse sudo permissions
  4. Kernel exploit research
- **Platform**: TryHackMe - Linux PrivEsc Room

### 🌐 Week 3-4: Networking Labs

#### Lab 1.3: Network Reconnaissance
- **Duration**: 5 hours
- **Difficulty**: Easy-Medium
- **Objectives**:
  - Perform comprehensive network scanning
  - Service enumeration
  - OS fingerprinting
- **Exercises**:
  1. Nmap scripting engine usage
  2. Masscan for large networks
  3. Banner grabbing techniques
  4. Create network topology map
- **Tools**: nmap, masscan, netcat, telnet

#### Lab 1.4: Traffic Analysis
- **Duration**: 6 hours
- **Difficulty**: Medium
- **Objectives**:
  - Packet capture và analysis
  - Protocol analysis
  - Identify malicious traffic
- **Exercises**:
  1. Capture và decode HTTP traffic
  2. Extract files from PCAP
  3. Identify C2 communication
  4. DNS tunneling detection
- **Tools**: Wireshark, tcpdump, NetworkMiner

### 🐍 Week 5-6: Python Security Labs

#### Lab 1.5: Python Security Tools Development
- **Duration**: 8 hours
- **Difficulty**: Medium
- **Objectives**:
  - Build security tools from scratch
  - Understand networking libraries
  - Automation scripting
- **Projects**:
  1. **Port Scanner**:
     ```python
     # Multi-threaded port scanner
     # Features: SYN scan, UDP scan, service detection
     ```
  2. **Password Cracker**:
     ```python
     # Dictionary attack tool
     # Support: MD5, SHA256, bcrypt
     ```
  3. **Web Scraper**:
     ```python
     # Extract emails, phone numbers from websites
     # Recursive crawling với depth limit
     ```
  4. **Keylogger** (Educational):
     ```python
     # Capture keystrokes (legal use only)
     # Email reports functionality
     ```

#### Lab 1.6: API Security Testing
- **Duration**: 4 hours
- **Difficulty**: Medium
- **Objectives**:
  - API enumeration
  - Authentication bypass
  - Rate limiting tests
- **Exercises**:
  1. Postman collection for testing
  2. JWT manipulation
  3. API fuzzing với Python
  4. GraphQL enumeration

### ☁️ Week 7-8: Cloud Security Labs

#### Lab 1.7: AWS Security Basics
- **Duration**: 6 hours
- **Difficulty**: Medium
- **Objectives**:
  - S3 bucket misconfigurations
  - IAM privilege escalation
  - EC2 security
- **Exercises**:
  1. Find public S3 buckets
  2. Exploit SSRF for metadata
  3. IAM policy analysis
  4. CloudTrail log analysis
- **Platform**: CloudGoat scenarios

#### Lab 1.8: Container Security
- **Duration**: 5 hours
- **Difficulty**: Medium-Hard
- **Objectives**:
  - Container escape techniques
  - Image vulnerability scanning
  - Kubernetes security
- **Exercises**:
  1. Docker breakout methods
  2. Scan images với Trivy/Clair
  3. K8s RBAC misconfigurations
  4. Secrets extraction
- **Tools**: Docker, kubectl, Trivy

---

## 🔐 PHASE 2: CORE SECURITY LABS (Tháng 4-8)

### 🎯 Week 9-12: Web Application Security Labs

#### Lab 2.1: SQL Injection Mastery
- **Duration**: 8 hours
- **Difficulty**: Medium-Hard
- **Objectives**:
  - Manual SQL injection
  - Blind SQLi techniques
  - Second-order SQLi
- **Exercises**:
  1. **Basic SQLi**:
     - Login bypass
     - UNION attacks
     - Database enumeration
  2. **Blind SQLi**:
     - Boolean-based
     - Time-based
     - Out-of-band
  3. **Advanced**:
     - WAF bypass techniques
     - Polyglot payloads
     - NoSQL injection
- **Platform**: PortSwigger Web Security Academy

#### Lab 2.2: XSS Advanced Exploitation
- **Duration**: 6 hours
- **Difficulty**: Medium-Hard
- **Objectives**:
  - XSS types mastery
  - Filter bypass
  - Chaining vulnerabilities
- **Exercises**:
  1. **Reflected XSS**:
     - Basic payloads
     - Encoding bypasses
     - CSP bypass
  2. **Stored XSS**:
     - BeEF integration
     - Keylogger deployment
     - Session hijacking
  3. **DOM XSS**:
     - Source/Sink analysis
     - Framework-specific XSS
     - Mutation XSS
- **Tools**: Burp Suite, BeEF, XSStrike

#### Lab 2.3: Authentication & Session Attacks
- **Duration**: 6 hours
- **Difficulty**: Hard
- **Objectives**:
  - Authentication bypasses
  - Session hijacking
  - JWT attacks
- **Exercises**:
  1. Brute force với rate limit bypass
  2. 2FA bypass techniques
  3. JWT signature attacks
  4. Session fixation
  5. OAuth misconfigurations
- **Real-world**: Bug bounty authentication bugs

#### Lab 2.4: Server-Side Attacks
- **Duration**: 8 hours
- **Difficulty**: Hard
- **Objectives**:
  - SSRF exploitation
  - XXE injection
  - Deserialization attacks
- **Exercises**:
  1. **SSRF**:
     - Cloud metadata extraction
     - Internal port scanning
     - Protocol smuggling
  2. **XXE**:
     - File disclosure
     - SSRF via XXE
     - Blind XXE
  3. **Deserialization**:
     - Java deserialization
     - Python pickle RCE
     - .NET exploitation

### 🛡️ Week 13-16: Defensive Security Labs

#### Lab 2.5: SIEM Implementation
- **Duration**: 10 hours
- **Difficulty**: Medium-Hard
- **Objectives**:
  - Log collection setup
  - Alert creation
  - Incident investigation
- **Exercises**:
  1. **Splunk Setup**:
     - Data ingestion
     - Search queries (SPL)
     - Dashboard creation
     - Alert rules
  2. **ELK Stack**:
     - Elasticsearch queries
     - Kibana visualizations
     - Logstash pipelines
     - Watcher alerts
  3. **Use Cases**:
     - Brute force detection
     - Data exfiltration alerts
     - Privilege escalation detection
- **Platform**: Splunk Fundamentals, ELK tutorials

#### Lab 2.6: Incident Response Simulation
- **Duration**: 8 hours
- **Difficulty**: Hard
- **Objectives**:
  - Incident detection
  - Forensics collection
  - Root cause analysis
- **Scenarios**:
  1. **Ransomware Attack**:
     - Initial detection
     - Containment steps
     - Evidence collection
     - Recovery planning
  2. **Data Breach**:
     - Log analysis
     - Timeline creation
     - Impact assessment
     - Reporting
  3. **APT Simulation**:
     - Threat hunting
     - IOC correlation
     - Attribution analysis
- **Tools**: Volatility, Autopsy, RITA

#### Lab 2.7: Malware Analysis Basics
- **Duration**: 10 hours
- **Difficulty**: Hard
- **Objectives**:
  - Static analysis
  - Dynamic analysis
  - Reverse engineering basics
- **Exercises**:
  1. **Static Analysis**:
     - PE header analysis
     - String extraction
     - Entropy analysis
     - YARA rules
  2. **Dynamic Analysis**:
     - Sandbox execution
     - Network behavior
     - Registry changes
     - API monitoring
  3. **Basic RE**:
     - x64dbg debugging
     - IDA Free basics
     - Unpacking techniques
- **Platform**: REMnux, FlareVM

### 🤖 Week 17-18: AI Security Labs

#### Lab 2.8: LLM Security Testing
- **Duration**: 6 hours
- **Difficulty**: Medium-Hard
- **Objectives**:
  - Prompt injection
  - Jailbreaking techniques
  - Data extraction
- **Exercises**:
  1. **Prompt Injection**:
     - Direct injection
     - Indirect injection
     - Payload obfuscation
  2. **Jailbreaking**:
     - DAN techniques
     - Role-playing attacks
     - Encoding bypasses
  3. **Privacy Attacks**:
     - Training data extraction
     - Model inversion
     - Membership inference
- **Platforms**: ChatGPT, Claude, local LLMs

#### Lab 2.9: Adversarial ML
- **Duration**: 8 hours
- **Difficulty**: Expert
- **Objectives**:
  - Create adversarial examples
  - Model poisoning
  - Backdoor attacks
- **Exercises**:
  1. Image classifier evasion
  2. Text classifier bypasses
  3. Model extraction attacks
  4. Federated learning attacks
- **Tools**: Adversarial Robustness Toolbox, CleverHans

---

## 🚀 PHASE 3: ADVANCED LABS (Tháng 9-12)

### 🔴 Week 19-22: Red Team Operations

#### Lab 3.1: Active Directory Exploitation
- **Duration**: 12 hours
- **Difficulty**: Expert
- **Objectives**:
  - AD enumeration
  - Lateral movement
  - Persistence techniques
- **Exercises**:
  1. **Enumeration**:
     - BloodHound analysis
     - PowerView usage
     - LDAP queries
  2. **Attacks**:
     - Kerberoasting
     - ASREPRoasting
     - Pass-the-Hash
     - Golden/Silver tickets
  3. **Persistence**:
     - DCSync
     - Skeleton keys
     - AdminSDHolder
- **Lab Environment**: GOAD, Vulnerable AD labs

#### Lab 3.2: C2 Infrastructure
- **Duration**: 10 hours
- **Difficulty**: Expert
- **Objectives**:
  - C2 setup và management
  - Evasion techniques
  - Post-exploitation
- **Exercises**:
  1. **Cobalt Strike**:
     - Team server setup
     - Malleable profiles
     - Beacon configuration
     - Lateral movement
  2. **Empire/Metasploit**:
     - Listener setup
     - Agent deployment
     - Module development
  3. **Custom C2**:
     - Build basic C2
     - Encryption implementation
     - Domain fronting
- **Infrastructure**: Cloud VPS, Domain setup

#### Lab 3.3: Physical Security & Social Engineering
- **Duration**: 8 hours
- **Difficulty**: Hard
- **Objectives**:
  - Lock picking basics
  - RFID/Badge cloning
  - Phishing campaigns
- **Exercises**:
  1. **Physical**:
     - Lock picking practice
     - RFID cloning với Proxmark
     - USB drops
  2. **Social Engineering**:
     - Phishing email creation
     - Vishing scenarios
     - Pretexting practice
  3. **OSINT**:
     - Target profiling
     - Social media reconnaissance
     - Data aggregation
- **Tools**: SET, Gophish, OSINT Framework

### 🔵 Week 23-26: Enterprise Security

#### Lab 3.4: Zero Trust Implementation
- **Duration**: 10 hours
- **Difficulty**: Hard
- **Objectives**:
  - Micro-segmentation
  - Identity-based access
  - Continuous verification
- **Exercises**:
  1. Design Zero Trust architecture
  2. Implement ZTNA solution
  3. Policy creation và enforcement
  4. Monitoring và compliance
- **Tools**: Open-source ZT solutions

#### Lab 3.5: DevSecOps Pipeline
- **Duration**: 12 hours
- **Difficulty**: Hard
- **Objectives**:
  - Secure CI/CD pipeline
  - Automated security testing
  - Container security
- **Implementation**:
  1. **SAST Integration**:
     - SonarQube setup
     - Custom rules
     - False positive management
  2. **DAST Integration**:
     - OWASP ZAP automation
     - API security testing
     - Results correlation
  3. **Container Security**:
     - Image scanning
     - Runtime protection
     - Admission controllers
  4. **Secrets Management**:
     - HashiCorp Vault
     - Key rotation
     - Least privilege
- **Platform**: GitLab CI/CD, Jenkins

### 🎮 Week 27-30: CTF & Bug Bounty

#### Lab 3.6: CTF Challenge Creation
- **Duration**: 15 hours
- **Difficulty**: Expert
- **Objectives**:
  - Design CTF challenges
  - Infrastructure setup
  - Scoring system
- **Create**:
  1. Web challenges (5 levels)
  2. Pwn challenges (3 levels)
  3. Crypto challenges (3 levels)
  4. Forensics challenges (3 levels)
  5. Reverse engineering (3 levels)
- **Platform**: CTFd deployment

#### Lab 3.7: Bug Bounty Automation
- **Duration**: 10 hours
- **Difficulty**: Hard
- **Objectives**:
  - Recon automation
  - Vulnerability scanning
  - Report generation
- **Build**:
  1. **Recon Pipeline**:
     ```bash
     # Subdomain enumeration
     # Port scanning
     # Technology detection
     # Screenshot capture
     ```
  2. **Scanning Automation**:
     - Nuclei templates
     - Custom scanners
     - False positive filtering
  3. **Monitoring**:
     - Asset monitoring
     - Change detection
     - Alert system
- **Tools**: Axiom, Nuclei, Amass

---

## 📊 PHASE 4: SPECIALIZATION LABS (Tháng 13-18)

### 🔬 Forensics Specialization

#### Lab 4.1: Memory Forensics Mastery
- **Duration**: 12 hours
- **Difficulty**: Expert
- **Exercises**:
  1. Process analysis với Volatility
  2. Malware detection in memory
  3. Registry hive extraction
  4. Network connection recovery
  5. Password extraction

#### Lab 4.2: Mobile Forensics
- **Duration**: 10 hours
- **Difficulty**: Expert
- **Exercises**:
  1. Android device acquisition
  2. iOS backup analysis
  3. App data extraction
  4. Deleted data recovery
  5. Timeline analysis

### ☁️ Cloud Specialization

#### Lab 4.3: Multi-Cloud Security
- **Duration**: 15 hours
- **Difficulty**: Expert
- **Exercises**:
  1. AWS, Azure, GCP security assessment
  2. Cloud-native attacks
  3. Serverless security
  4. Multi-cloud governance
  5. Compliance automation

#### Lab 4.4: Kubernetes Advanced Security
- **Duration**: 12 hours
- **Difficulty**: Expert
- **Exercises**:
  1. Advanced RBAC
  2. Network policies
  3. Service mesh security
  4. Runtime protection
  5. Compliance scanning

### 🤖 AI/ML Specialization

#### Lab 4.5: AI Red Teaming
- **Duration**: 15 hours
- **Difficulty**: Expert
- **Exercises**:
  1. Model stealing attacks
  2. Backdoor injection
  3. Privacy attacks
  4. Robustness testing
  5. Explainability attacks

#### Lab 4.6: Secure ML Pipeline
- **Duration**: 12 hours
- **Difficulty**: Expert
- **Exercises**:
  1. Secure training infrastructure
  2. Model versioning và integrity
  3. Differential privacy implementation
  4. Federated learning security
  5. Model monitoring

---

## 🎯 CAPSTONE PROJECTS

### Project 1: Build a Security Platform
**Duration**: 4 weeks
**Objective**: Create comprehensive security platform
**Components**:
- Vulnerability scanner
- SIEM integration
- Incident response automation
- Threat intelligence feeds
- Reporting dashboard

### Project 2: Red Team Operation
**Duration**: 3 weeks
**Objective**: Full red team engagement simulation
**Phases**:
- Reconnaissance
- Initial access
- Privilege escalation
- Lateral movement
- Data exfiltration
- Reporting

### Project 3: Security Research
**Duration**: 4 weeks
**Objective**: Original security research
**Options**:
- Find 0-day vulnerability
- Develop new attack technique
- Create defensive tool
- Write security paper
- Conference presentation

### Project 4: CTF Platform Development
**Duration**: 3 weeks
**Objective**: Create educational CTF platform
**Features**:
- 20+ challenges
- Automated scoring
- Hint system
- Write-up submission
- Leaderboard

---

## 📈 SKILL PROGRESSION TRACKING

### Beginner Milestones (Month 1-3)
- [ ] 50 TryHackMe rooms completed
- [ ] 10 Python security scripts
- [ ] 5 CTF participations
- [ ] Basic home lab setup
- [ ] 20 blog posts

### Intermediate Milestones (Month 4-8)
- [ ] 30 HackTheBox machines
- [ ] 5 CVE submissions
- [ ] 3 bug bounties
- [ ] Security+ certified
- [ ] 1 tool published

### Advanced Milestones (Month 9-12)
- [ ] OSCP certification
- [ ] 10+ CVEs
- [ ] $10k bug bounties
- [ ] Conference talk
- [ ] Job placement

### Expert Milestones (Month 13-18)
- [ ] Team lead role
- [ ] Published research
- [ ] Tool dengan 100+ stars
- [ ] Mentor 5 beginners
- [ ] 6-figure position

---

## 🛠️ LAB ENVIRONMENT SETUP

### Hardware Requirements
**Minimum**:
- CPU: 4 cores
- RAM: 16GB
- Storage: 500GB SSD
- Network: 100Mbps

**Recommended**:
- CPU: 8+ cores
- RAM: 32GB
- Storage: 1TB NVMe
- GPU: For ML labs
- Network: 1Gbps

### Software Stack
```bash
# Base OS
- Ubuntu 22.04 LTS (Host)
- VMware Workstation Pro

# VMs
- Kali Linux 2024.x
- Windows 10/11
- Ubuntu Server
- ParrotOS
- REMnux
- SIFT Workstation

# Containers
- Docker
- Kubernetes (minikube)
- Docker Compose

# Cloud Accounts
- AWS Free Tier
- Azure Student
- GCP Free Credits
- DigitalOcean $200 credit
```

---

## 📚 REFERENCE MATERIALS

### Books (Must Read)
1. "The Web Application Hacker's Handbook" - Stuttard
2. "The Hacker Playbook 3" - Peter Kim
3. "Practical Malware Analysis" - Sikorski
4. "Black Hat Python" - Justin Seitz
5. "Gray Hat Hacking" - Harper

### Online Courses
1. Offensive Security - PEN-200
2. SANS SEC560 - Network Penetration Testing
3. eLearnSecurity - eJPT/eCPPT
4. TCM Security - Practical Ethical Hacking
5. Pentester Academy - Various

### YouTube Channels
1. IppSec - HTB walkthroughs
2. John Hammond - CTF và security
3. LiveOverflow - Binary exploitation
4. The Cyber Mentor - Practical tutorials
5. STÖK - Bug bounty

### Podcasts
1. Darknet Diaries
2. Security Now
3. The Privacy, Security, and OSINT Show
4. Risky Business
5. Hacked

---

*"Practice makes perfect. Every lab is a step toward mastery."*

**Document Version**: 1.0.0  
**Created**: September 2025  
**Next Update**: December 2025
