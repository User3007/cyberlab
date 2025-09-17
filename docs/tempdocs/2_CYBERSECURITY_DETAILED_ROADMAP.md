# 🎯 LỘ TRÌNH HỌC CYBERSECURITY CHI TIẾT - SINH VIÊN CNTT

## 📋 TỔNG QUAN KHOÁ HỌC

### 🎓 Thông tin chung
- **Đối tượng**: Sinh viên CNTT năm 2-4, người mới chuyển ngành
- **Thời gian**: 12-18 tháng (học song song với chương trình chính quy)
- **Cam kết**: 15-20 giờ/tuần (2-3 giờ/ngày)
- **Mục tiêu**: Entry-level Security Engineer/Analyst
- **Mức lương kỳ vọng**: $60-80k (entry), $100-150k (3 năm kinh nghiệm)

### 🎯 Kết quả học tập
✅ **Kỹ năng cứng**: Linux, Networking, Python, Web Security, Cloud Security  
✅ **Chứng chỉ**: 2-3 certifications (Security+, CySA+, AWS Security)  
✅ **Kinh nghiệm**: Portfolio với 20+ projects, CTF participation, Bug bounty  
✅ **Soft skills**: Technical communication, Documentation, Presentation  
✅ **Network**: 100+ LinkedIn connections, Community participation  

---

## 📅 PHASE 1: NỀN TẢNG CƠ BẢN (12 tuần - 3 tháng)

### 🎯 Mục tiêu Phase 1
- Nắm vững kiến thức CNTT cốt lõi
- Hiểu rõ về networking và security fundamentals
- Có thể viết Python scripts for security
- Setup được lab environment

### MODULE 1.1: LINUX & SYSTEM ADMINISTRATION (3 tuần)
**Thời gian**: 3 tuần × 15 giờ = 45 giờ  
**Độ ưu tiên**: CRITICAL ⭐⭐⭐

#### Tuần 1: Linux Basics
**Mục tiêu**: Thành thạo Linux command line

**Nội dung học**:
- **Day 1-2**: Linux installation & file system
  - Cài đặt Kali Linux VM
  - File system hierarchy (/bin, /etc, /var, /home)
  - Basic navigation (cd, ls, pwd, find)
  - File operations (cp, mv, rm, mkdir, rmdir)

- **Day 3-4**: Permissions & Users
  - User management (useradd, usermod, passwd)
  - Permission system (chmod, chown, chgrp)
  - Special permissions (SUID, SGID, sticky bit)
  - sudo configuration

- **Day 5-7**: Process & Services
  - Process management (ps, top, htop, kill)
  - Service management (systemctl, systemd)
  - Job control (jobs, bg, fg, nohup)
  - Cron jobs & scheduling

**Labs thực hành**:
- [ ] Cài đặt và cấu hình Kali Linux VM
- [ ] Tạo user accounts và set permissions
- [ ] Viết script backup tự động
- [ ] Setup SSH server và configure firewall
- [ ] Monitor system resources

**Resources**:
- Linux Journey (free online course)
- OverTheWire Bandit wargame
- Linux Command Line Bootcamp (Udemy)

#### Tuần 2: Advanced Linux & Scripting
**Mục tiêu**: Shell scripting và system administration

**Nội dung học**:
- **Day 1-2**: Text Processing
  - Text manipulation (grep, sed, awk)
  - File comparison (diff, comm, sort, uniq)
  - Regular expressions
  - Log analysis techniques

- **Day 3-4**: Bash Scripting
  - Variables, loops, conditions
  - Functions và parameter passing
  - Error handling
  - Script debugging

- **Day 5-7**: Network Tools
  - Network commands (netstat, ss, lsof)
  - Packet analysis (tcpdump basics)
  - Network configuration
  - Troubleshooting tools

**Labs thực hành**:
- [ ] Viết script phân tích log files
- [ ] Tạo backup và restore scripts
- [ ] Network monitoring script
- [ ] System health check automation
- [ ] User audit script

#### Tuần 3: System Security & Hardening
**Mục tiêu**: Linux security best practices

**Nội dung học**:
- **Day 1-2**: System Hardening
  - SSH hardening
  - Firewall configuration (iptables, ufw)
  - Fail2ban setup
  - System updates & patching

- **Day 3-4**: Logging & Monitoring
  - System logs (/var/log/)
  - Centralized logging
  - Intrusion detection basics
  - Performance monitoring

- **Day 5-7**: Security Tools
  - Basic security tools (nmap, netcat)
  - File integrity monitoring
  - Antivirus & malware scanning
  - Security benchmarks

**Labs thực hành**:
- [ ] Harden Ubuntu/CentOS server
- [ ] Setup centralized logging với rsyslog
- [ ] Configure intrusion detection
- [ ] Security compliance checking
- [ ] Incident response preparation

**Assessment Week 3**:
- [ ] Linux proficiency test (50 commands)
- [ ] Script a complete system audit tool
- [ ] Setup production-ready server

---

### MODULE 1.2: NETWORKING FUNDAMENTALS (3 tuần)
**Thời gian**: 3 tuần × 15 giờ = 45 giờ  
**Độ ưu tiên**: CRITICAL ⭐⭐⭐

#### Tuần 4: Network Basics & Protocols
**Mục tiêu**: Hiểu sâu về networking

**Nội dung học**:
- **Day 1-2**: OSI & TCP/IP Model
  - 7 layers của OSI model
  - TCP/IP stack và encapsulation
  - Headers và packet structure
  - Protocol interactions

- **Day 3-4**: Core Protocols
  - IP addressing & subnetting (IPv4/IPv6)
  - TCP vs UDP characteristics
  - ICMP và network diagnostics
  - ARP và MAC address resolution

- **Day 5-7**: Application Protocols
  - HTTP/HTTPS deep dive
  - DNS operation & security
  - DHCP, FTP, SSH, Telnet
  - Email protocols (SMTP, POP3, IMAP)

**Labs thực hành**:
- [ ] Wireshark packet analysis
- [ ] TCP handshake capture
- [ ] DNS query analysis
- [ ] HTTP vs HTTPS comparison
- [ ] Network topology mapping

#### Tuần 5: Network Infrastructure & Security
**Mục tiêu**: Network devices và security

**Nội dung học**:
- **Day 1-2**: Network Devices
  - Routers vs Switches vs Hubs
  - VLANs và network segmentation
  - Firewalls types và rules
  - Load balancers

- **Day 3-4**: Network Security
  - Network attacks (DoS, MITM, ARP poisoning)
  - IDS/IPS concepts
  - Network access control
  - VPN technologies

- **Day 5-7**: Wireless Security
  - Wi-Fi protocols (WEP, WPA, WPA2, WPA3)
  - Wireless attacks
  - Bluetooth security
  - Radio frequency basics

**Labs thực hành**:
- [ ] VLAN configuration
- [ ] Firewall rule creation
- [ ] Wi-Fi security assessment
- [ ] Network vulnerability scanning
- [ ] VPN setup và testing

#### Tuần 6: Advanced Networking & Troubleshooting
**Mục tiêu**: Advanced concepts và troubleshooting

**Nội dung học**:
- **Day 1-2**: Advanced Concepts
  - BGP và routing protocols
  - QoS và traffic management
  - Network optimization
  - SD-WAN concepts

- **Day 3-4**: Network Monitoring
  - SNMP monitoring
  - Network performance metrics
  - Bandwidth analysis
  - Network documentation

- **Day 5-7**: Troubleshooting
  - Systematic troubleshooting approach
  - Common network issues
  - Performance problems
  - Security incidents

**Labs thực hành**:
- [ ] Complete network topology design
- [ ] Performance benchmarking
- [ ] Troubleshooting scenarios
- [ ] Network documentation project
- [ ] Monitoring solution setup

**Assessment Week 6**:
- [ ] Network knowledge exam
- [ ] Design enterprise network
- [ ] Troubleshoot network problems

---

### MODULE 1.3: PROGRAMMING FOR SECURITY (3 tuần)
**Thời gian**: 3 tuần × 15 giờ = 45 giờ  
**Độ ưu tiên**: CRITICAL ⭐⭐⭐

#### Tuần 7: Python Fundamentals
**Mục tiêu**: Python basics for security

**Nội dung học**:
- **Day 1-2**: Python Basics
  - Syntax, variables, data types
  - Control structures (if, for, while)
  - Functions và modules
  - Exception handling

- **Day 3-4**: Data Structures
  - Lists, tuples, dictionaries
  - Sets và advanced operations
  - File handling
  - String manipulation

- **Day 5-7**: Object-Oriented Programming
  - Classes và objects
  - Inheritance và polymorphism
  - Error handling
  - Best practices

**Labs thực hành**:
- [ ] Simple calculator program
- [ ] File processing utilities
- [ ] Data parsing scripts
- [ ] Basic web scraper
- [ ] Log analyzer tool

#### Tuần 8: Python for Security
**Mục tiêu**: Security-focused programming

**Nội dung học**:
- **Day 1-2**: Network Programming
  - Socket programming
  - TCP/UDP clients & servers
  - HTTP requests với requests library
  - API interactions

- **Day 3-4**: Security Libraries
  - Scapy for packet manipulation
  - Paramiko for SSH automation
  - Cryptography library
  - BeautifulSoup for web parsing

- **Day 5-7**: Security Tools Development
  - Port scanner development
  - Password attack tools
  - Log analysis automation
  - Vulnerability scanners

**Labs thực hành**:
- [ ] TCP port scanner
- [ ] HTTP fuzzer
- [ ] Password brute forcer
- [ ] Network discovery tool
- [ ] Vulnerability scanner prototype

#### Tuần 9: Web Technologies & Automation
**Mục tiêu**: Web technologies và automation

**Nội dung học**:
- **Day 1-2**: Web Basics
  - HTML, CSS, JavaScript fundamentals
  - HTTP methods và status codes
  - Cookies và sessions
  - Web architecture

- **Day 3-4**: Web Security Basics
  - Input validation
  - SQL injection basics
  - XSS vulnerabilities
  - Authentication mechanisms

- **Day 5-7**: Automation & Integration
  - CI/CD basics
  - Git version control
  - Docker containers
  - API development

**Labs thực hành**:
- [ ] Vulnerable web application
- [ ] Web vulnerability scanner
- [ ] Automation scripts
- [ ] API testing tools
- [ ] Container security scanner

**Assessment Week 9**:
- [ ] Python programming test
- [ ] Build complete security tool
- [ ] Automation project

---

### MODULE 1.4: CLOUD & MODERN TECHNOLOGIES (3 tuần)
**Thời gian**: 3 tuần × 15 giờ = 45 giờ  
**Độ ưu tiên**: HIGH ⭐⭐

#### Tuần 10: Cloud Fundamentals
**Mục tiêu**: Cloud computing basics

**Nội dung học**:
- **Day 1-2**: Cloud Concepts
  - IaaS, PaaS, SaaS models
  - Public, private, hybrid cloud
  - Cloud economics
  - Service comparisons

- **Day 3-4**: AWS Basics
  - AWS account setup
  - EC2, S3, VPC basics
  - IAM fundamentals
  - Basic security groups

- **Day 5-7**: Azure & GCP Overview
  - Azure fundamentals
  - Google Cloud basics
  - Multi-cloud concepts
  - Cloud migration basics

**Labs thực hành**:
- [ ] AWS free tier setup
- [ ] Deploy web application on cloud
- [ ] Cloud storage configuration
- [ ] Basic cloud networking
- [ ] Cloud cost optimization

#### Tuần 11: Containerization & DevOps
**Mục tiêu**: Modern deployment methods

**Nội dung học**:
- **Day 1-2**: Docker Fundamentals
  - Container concepts
  - Dockerfile creation
  - Image management
  - Container networking

- **Day 3-4**: Kubernetes Basics
  - K8s architecture
  - Pods, services, deployments
  - Basic security concepts
  - Monitoring & logging

- **Day 5-7**: CI/CD Pipeline
  - GitLab/GitHub Actions
  - Pipeline security
  - Infrastructure as Code basics
  - Monitoring & alerting

**Labs thực hành**:
- [ ] Multi-container application
- [ ] Kubernetes deployment
- [ ] CI/CD pipeline setup
- [ ] Container security scanning
- [ ] Infrastructure automation

#### Tuần 12: AI/ML & Emerging Technologies
**Mục tiêu**: Future technologies

**Nội dung học**:
- **Day 1-2**: AI/ML Basics
  - Machine learning concepts
  - AI security implications
  - LLM security
  - Prompt engineering

- **Day 3-4**: Emerging Tech Security
  - IoT security basics
  - Blockchain fundamentals
  - 5G security
  - Quantum computing impact

- **Day 5-7**: Technology Integration
  - Security architecture design
  - Technology stack evaluation
  - Future trend analysis
  - Continuous learning

**Labs thực hành**:
- [ ] AI-powered security tool
- [ ] IoT device assessment
- [ ] Blockchain analysis
- [ ] Technology research project
- [ ] Future-proofing strategies

**Assessment Week 12**:
- [ ] Technology knowledge assessment
- [ ] Cloud architecture design
- [ ] Integration project

---

## 🔒 PHASE 2: CORE SECURITY (16 tuần - 4 tháng)

### 🎯 Mục tiêu Phase 2
- Nắm vững security fundamentals
- Thành thạo web application security
- Có thể thực hiện basic penetration testing
- Hiểu về defensive security

### MODULE 2.1: SECURITY FUNDAMENTALS (4 tuần)
**Thời gian**: 4 tuần × 15 giờ = 60 giờ  
**Độ ưu tiên**: CRITICAL ⭐⭐⭐

#### Tuần 13: Security Principles & Cryptography
**Mục tiêu**: Core security concepts

**Nội dung học**:
- **Day 1-2**: CIA Triad & Extended Principles
  - Confidentiality mechanisms
  - Integrity verification
  - Availability assurance
  - Non-repudiation
  - Authentication methods

- **Day 3-4**: Cryptography Fundamentals
  - Symmetric encryption (AES)
  - Asymmetric encryption (RSA, ECC)
  - Hash functions (SHA-256, bcrypt)
  - Digital signatures

- **Day 5-7**: PKI & Certificate Management
  - Certificate authorities
  - X.509 certificates
  - SSL/TLS protocols
  - Certificate validation

**Labs thực hành**:
- [ ] Implement encryption/decryption
- [ ] Certificate generation
- [ ] PKI infrastructure setup
- [ ] Cryptographic attack simulation
- [ ] Secure communication channel

#### Tuần 14: Threat Landscape & Risk Management
**Mục tiêu**: Understanding threats và risks

**Nội dung học**:
- **Day 1-2**: Threat Actors & Vectors
  - APT groups analysis
  - Cybercriminal organizations
  - Nation-state actors
  - Insider threats

- **Day 3-4**: Attack Frameworks
  - MITRE ATT&CK
  - Cyber Kill Chain
  - Diamond Model
  - Threat modeling

- **Day 5-7**: Risk Assessment
  - Risk identification
  - Vulnerability assessment
  - Risk calculation
  - Risk treatment strategies

**Labs thực hành**:
- [ ] Threat intelligence gathering
- [ ] Risk assessment project
- [ ] Threat modeling exercise
- [ ] Attack simulation
- [ ] Risk management framework

#### Tuần 15: Security Models & Frameworks
**Mục tiêu**: Security governance

**Nội dung học**:
- **Day 1-2**: Security Models
  - Bell-LaPadula model
  - Biba integrity model
  - Clark-Wilson model
  - Chinese Wall model

- **Day 3-4**: Access Control
  - RBAC implementation
  - ABAC concepts
  - MAC vs DAC
  - Least privilege

- **Day 5-7**: Compliance Frameworks
  - ISO 27001 basics
  - NIST Cybersecurity Framework
  - CIS Controls
  - Regulatory compliance

**Labs thực hành**:
- [ ] Access control implementation
- [ ] Security policy development
- [ ] Compliance assessment
- [ ] Security framework mapping
- [ ] Audit preparation

#### Tuần 16: Incident Response & Forensics
**Mục tiêu**: Incident handling

**Nội dung học**:
- **Day 1-2**: Incident Response Process
  - Preparation phase
  - Detection & analysis
  - Containment strategies
  - Recovery & lessons learned

- **Day 3-4**: Digital Forensics Basics
  - Evidence collection
  - Chain of custody
  - Forensic tools
  - Analysis techniques

- **Day 5-7**: Business Continuity
  - BCP development
  - Disaster recovery
  - RTO/RPO planning
  - Testing & exercises

**Labs thực hành**:
- [ ] Incident response playbook
- [ ] Forensic analysis exercise
- [ ] BCP development
- [ ] Tabletop exercise
- [ ] Recovery testing

**Assessment Week 16**:
- [ ] Security fundamentals exam
- [ ] Threat assessment project
- [ ] Incident response simulation

---

### MODULE 2.2: WEB APPLICATION SECURITY (4 tuần)
**Thời gian**: 4 tuần × 15 giờ = 60 giờ  
**Độ ưu tiên**: CRITICAL ⭐⭐⭐

#### Tuần 17: OWASP Top 10 Deep Dive
**Mục tiêu**: Master web vulnerabilities

**Nội dung học**:
- **Day 1-2**: Injection Attacks
  - SQL injection types
  - NoSQL injection
  - LDAP injection
  - Command injection

- **Day 3-4**: Broken Authentication
  - Session management flaws
  - Password attacks
  - MFA bypass
  - JWT vulnerabilities

- **Day 5-7**: Sensitive Data Exposure
  - Data classification
  - Encryption in transit/rest
  - Data leakage prevention
  - Privacy protection

**Labs thực hành**:
- [ ] SQL injection exploitation
- [ ] Authentication bypass
- [ ] Data extraction attacks
- [ ] DVWA/WebGoat completion
- [ ] Custom vulnerability scanner

#### Tuần 18: Advanced Web Attacks
**Mục tiêu**: Advanced attack techniques

**Nội dung học**:
- **Day 1-2**: XSS & CSRF
  - Stored XSS exploitation
  - Reflected XSS
  - DOM-based XSS
  - CSRF attack chains

- **Day 3-4**: Server-Side Attacks
  - SSRF exploitation
  - XXE attacks
  - Template injection
  - Deserialization flaws

- **Day 5-7**: Business Logic Flaws
  - Workflow bypass
  - Race conditions
  - Price manipulation
  - Authorization flaws

**Labs thực hành**:
- [ ] XSS payload development
- [ ] CSRF proof-of-concept
- [ ] SSRF exploitation
- [ ] Business logic testing
- [ ] Advanced web scanner

#### Tuần 19: API Security & Modern Web
**Mục tiêu**: API và modern web security

**Nội dung học**:
- **Day 1-2**: REST API Security
  - API authentication
  - OAuth 2.0 flows
  - Rate limiting bypass
  - API fuzzing

- **Day 3-4**: GraphQL Security
  - GraphQL fundamentals
  - Query complexity attacks
  - Authorization bypass
  - Information disclosure

- **Day 5-7**: Modern Web Technologies
  - SPA security
  - WebSocket attacks
  - WebAssembly security
  - PWA security considerations

**Labs thực hành**:
- [ ] API security testing
- [ ] GraphQL penetration testing
- [ ] JWT token manipulation
- [ ] Modern web app assessment
- [ ] API fuzzing tool

#### Tuần 20: Web Security Tools & Automation
**Mục tiêu**: Tool mastery và automation

**Nội dung học**:
- **Day 1-2**: Burp Suite Mastery
  - Advanced Burp features
  - Extension development
  - Automated scanning
  - Custom payloads

- **Day 3-4**: Alternative Tools
  - OWASP ZAP
  - SQLMap mastery
  - Commix, XSStrike
  - Custom tool development

- **Day 5-7**: Automation & Integration
  - CI/CD security testing
  - DAST integration
  - Security pipeline
  - Reporting automation

**Labs thực hành**:
- [ ] Burp extension development
- [ ] Automated testing pipeline
- [ ] Custom web scanner
- [ ] Security reporting tool
- [ ] CI/CD integration

**Assessment Week 20**:
- [ ] Web security certification
- [ ] Complete web app pentest
- [ ] Vulnerability research

---

### MODULE 2.3: NETWORK SECURITY & PENETRATION TESTING (4 tuần)
**Thời gian**: 4 tuần × 15 giờ = 60 giờ  
**Độ ưu tiên**: HIGH ⭐⭐

#### Tuần 21: Network Reconnaissance
**Mục tiêu**: Information gathering

**Nội dung học**:
- **Day 1-2**: Passive Reconnaissance
  - OSINT techniques
  - Google dorking
  - Social media intelligence
  - DNS enumeration

- **Day 3-4**: Active Reconnaissance
  - Network discovery
  - Port scanning techniques
  - Service enumeration
  - OS fingerprinting

- **Day 5-7**: Advanced Enumeration
  - SNMP enumeration
  - SMB enumeration
  - Web directory bruteforcing
  - Vulnerability identification

**Labs thực hành**:
- [ ] Comprehensive OSINT report
- [ ] Network discovery scripts
- [ ] Service enumeration automation
- [ ] Vulnerability assessment
- [ ] Reconnaissance framework

#### Tuần 22: Network Exploitation
**Mục tiêu**: Network attack techniques

**Nội dung học**:
- **Day 1-2**: Metasploit Framework
  - MSF architecture
  - Exploit development
  - Payload generation
  - Post-exploitation modules

- **Day 3-4**: Manual Exploitation
  - Buffer overflow basics
  - Remote code execution
  - Privilege escalation
  - Persistence techniques

- **Day 5-7**: Network Attacks
  - ARP poisoning
  - DNS spoofing
  - MITM attacks
  - Wireless attacks

**Labs thực hành**:
- [ ] Metasploit lab environment
- [ ] Custom exploit development
- [ ] Network attack simulation
- [ ] Privilege escalation chains
- [ ] Persistence mechanisms

#### Tuần 23: Post-Exploitation & Lateral Movement
**Mục tiêu**: Advanced attack techniques

**Nội dung học**:
- **Day 1-2**: Windows Post-Exploitation
  - Windows enumeration
  - Registry manipulation
  - Service exploitation
  - Token manipulation

- **Day 3-4**: Linux Post-Exploitation
  - Linux privilege escalation
  - Kernel exploits
  - Cron job abuse
  - SSH key manipulation

- **Day 5-7**: Lateral Movement
  - Network pivoting
  - Tunneling techniques
  - Credential harvesting
  - Domain enumeration

**Labs thực hành**:
- [ ] Windows privilege escalation
- [ ] Linux privilege escalation
- [ ] Network pivoting lab
- [ ] Credential dumping
- [ ] Domain compromise simulation

#### Tuần 24: Defensive Security & Blue Team
**Mục tiêu**: Defensive perspectives

**Nội dung học**:
- **Day 1-2**: Network Defense
  - Firewall configuration
  - IDS/IPS deployment
  - Network segmentation
  - Monitoring implementation

- **Day 3-4**: SIEM & Log Analysis
  - SIEM architecture
  - Log correlation rules
  - Alert tuning
  - Investigation techniques

- **Day 5-7**: Threat Hunting
  - Hunt hypothesis development
  - IOC hunting
  - Behavioral analysis
  - Hunt tool usage

**Labs thực hành**:
- [ ] SIEM deployment
- [ ] Detection rule development
- [ ] Threat hunting exercise
- [ ] Blue team defense
- [ ] Security monitoring

**Assessment Week 24**:
- [ ] Network penetration test
- [ ] Blue team exercise
- [ ] Security tool development

---

### MODULE 2.4: CLOUD SECURITY (4 tuần)
**Thời gian**: 4 tuần × 15 giờ = 60 giờ  
**Độ ưu tiên**: HIGH ⭐⭐

#### Tuần 25: AWS Security Deep Dive
**Mục tiêu**: AWS security mastery

**Nội dung học**:
- **Day 1-2**: AWS Security Services
  - IAM best practices
  - VPC security design
  - Security Groups vs NACLs
  - CloudTrail implementation

- **Day 3-4**: AWS Security Tools
  - GuardDuty setup
  - Security Hub integration
  - Config rules
  - Systems Manager

- **Day 5-7**: AWS Penetration Testing
  - AWS pentest methodology
  - S3 bucket security
  - Lambda security
  - Container security

**Labs thực hành**:
- [ ] Secure AWS architecture
- [ ] IAM policy creation
- [ ] Security monitoring setup
- [ ] AWS penetration testing
- [ ] Compliance automation

#### Tuần 26: Azure & Multi-Cloud Security
**Mục tiêu**: Multi-cloud security

**Nội dung học**:
- **Day 1-2**: Azure Security
  - Azure AD security
  - Network security groups
  - Azure Security Center
  - Key Vault management

- **Day 3-4**: GCP Security
  - Cloud IAM
  - VPC security
  - Security Command Center
  - Cloud KMS

- **Day 5-7**: Multi-Cloud Strategy
  - Cloud security frameworks
  - CSPM solutions
  - CWPP implementation
  - Compliance management

**Labs thực hành**:
- [ ] Azure security setup
- [ ] GCP security configuration
- [ ] Multi-cloud monitoring
- [ ] Cloud compliance checking
- [ ] Cross-cloud security

#### Tuần 27: Container & Kubernetes Security
**Mục tiêu**: Container security

**Nội dung học**:
- **Day 1-2**: Docker Security
  - Image security scanning
  - Runtime security
  - Docker bench security
  - Container isolation

- **Day 3-4**: Kubernetes Security
  - K8s security architecture
  - RBAC configuration
  - Network policies
  - Pod security standards

- **Day 5-7**: DevSecOps Integration
  - CI/CD security
  - Infrastructure as Code security
  - Security as Code
  - Compliance automation

**Labs thực hành**:
- [ ] Container security pipeline
- [ ] Kubernetes hardening
- [ ] Security policy enforcement
- [ ] Runtime protection
- [ ] Compliance automation

#### Tuần 28: Cloud Incident Response
**Mục tiêu**: Cloud IR capabilities

**Nội dung học**:
- **Day 1-2**: Cloud IR Planning
  - Cloud-specific IR procedures
  - Evidence collection
  - Forensics in cloud
  - Legal considerations

- **Day 3-4**: Automation & Orchestration
  - SOAR for cloud
  - Automated response
  - Runbook development
  - Integration strategies

- **Day 5-7**: Advanced Cloud Security
  - Zero Trust in cloud
  - Serverless security
  - API gateway security
  - Future trends

**Labs thực hành**:
- [ ] Cloud IR playbook
- [ ] Automated response system
- [ ] Cloud forensics exercise
- [ ] Zero Trust implementation
- [ ] Advanced security architecture

**Assessment Week 28**:
- [ ] Cloud security certification prep
- [ ] Cloud architecture design
- [ ] Security automation project

---

## 🚀 PHASE 3: SPECIALIZATION & PROFESSIONAL (12 tuần - 3 tháng)

### 🎯 Mục tiêu Phase 3
- Chọn specialization path
- Develop professional portfolio
- Prepare for job market
- Build professional network

### SPECIALIZATION PATHS (8 tuần)

#### PATH A: PENETRATION TESTER 🔴
**Tuần 29-36**: Advanced pentesting skills

**Core Skills**:
- Advanced exploitation techniques
- Active Directory attacks  
- Mobile application security
- Social engineering
- Red team operations

**Certifications**: OSCP, eJPT, PenTest+
**Career Target**: Junior Penetration Tester
**Salary Range**: $65-85k entry level

#### PATH B: SOC ANALYST 🔵  
**Tuần 29-36**: Blue team capabilities

**Core Skills**:
- SIEM mastery (Splunk/ELK)
- Threat hunting
- Incident response
- Digital forensics
- Malware analysis

**Certifications**: CySA+, GCIH, SANS
**Career Target**: SOC Analyst Level 1-2
**Salary Range**: $55-75k entry level

#### PATH C: CLOUD SECURITY ENGINEER ☁️
**Tuần 29-36**: Cloud security specialization

**Core Skills**:
- Multi-cloud security
- DevSecOps automation
- Container security
- Compliance management
- Infrastructure as Code

**Certifications**: AWS Security, Azure Security, CKS
**Career Target**: Cloud Security Engineer
**Salary Range**: $75-95k entry level

#### PATH D: APPLICATION SECURITY ENGINEER 🔒
**Tuần 29-36**: AppSec focus

**Core Skills**:
- SAST/DAST implementation
- Secure code review
- API security
- DevSecOps integration
- Bug bounty hunting

**Certifications**: CSSLP, GWEB, Bug bounty success
**Career Target**: Application Security Engineer
**Salary Range**: $70-90k entry level

### PROFESSIONAL DEVELOPMENT (4 tuần)

#### Tuần 37-38: Portfolio Development
**Mục tiêu**: Professional portfolio

**Activities**:
- GitHub repository cleanup
- Technical blog writing
- Project documentation
- Video demonstrations
- Case study development

**Deliverables**:
- [ ] Professional GitHub profile
- [ ] Technical blog (10+ posts)
- [ ] Portfolio website
- [ ] Video demonstrations
- [ ] Professional resume

#### Tuần 39-40: Job Preparation
**Mục tiêu**: Job readiness

**Activities**:
- Interview preparation
- Technical skill assessment
- Salary negotiation training
- Professional networking
- Company research

**Deliverables**:
- [ ] Interview preparation guide
- [ ] Technical skill assessment
- [ ] Negotiation strategy
- [ ] Network of 100+ contacts
- [ ] Target company list

---

## 🔄 PHASE 4: CONTINUOUS LEARNING (Ongoing)

### 📚 Continuous Education Framework

#### Daily Routine (1-2 giờ/ngày)
- **Morning (30 phút)**: Security news và threat intelligence
- **Evening (60-90 phút)**: Hands-on practice, CTF, hoặc learning

#### Weekly Goals
- Complete 1 new lab/exercise
- Read 2 technical articles/papers
- Contribute to 1 open source project
- Network với 5 professionals mới

#### Monthly Objectives
- Complete 1 certification study module
- Participate trong 2 CTF competitions
- Write 2 technical blog posts
- Attend 1 virtual conference/webinar

#### Quarterly Milestones
- Achieve 1 professional certification
- Complete 1 major project
- Present tại 1 meetup/conference
- Mentor 1 junior person

---

## 📊 ASSESSMENT & TRACKING

### 🎯 Progress Tracking System

#### Weekly Assessments
- Technical skill tests
- Hands-on lab completion
- Project milestone reviews
- Peer feedback sessions

#### Monthly Reviews
- Comprehensive skill assessment
- Portfolio review
- Career goal adjustment
- Learning path optimization

#### Quarterly Evaluations
- Professional certification attempts
- Major project presentations
- Career advancement planning
- Salary/role progression review

### 📈 Success Metrics

#### Technical Metrics
- **Month 3**: Complete 50+ labs, basic Python proficiency
- **Month 6**: First security certification, CTF participation
- **Month 9**: Specialization expertise, advanced projects
- **Month 12**: Job-ready portfolio, professional network

#### Professional Metrics
- **LinkedIn**: 500+ connections trong security field
- **GitHub**: 20+ repositories, active contributions
- **Blog**: 50+ technical posts, community recognition
- **Certifications**: 2-3 professional certifications

#### Career Metrics
- **Month 6**: Internship opportunities
- **Month 9**: Entry-level interviews
- **Month 12**: Job offers và salary negotiations
- **Month 18**: Career advancement opportunities

---

## 🛠️ TOOLS & RESOURCES

### 💻 Essential Software Setup

#### Virtual Lab Environment
```bash
# Core VMs cần có:
- Kali Linux (Primary attack platform)
- Ubuntu Server (Target và blue team)
- Windows 10 (Target và analysis)
- pfSense (Network security)
- Security Onion (SIEM/NSM)
```

#### Development Environment
```bash
# Essential tools:
- VS Code với security extensions
- Python 3.9+ với security libraries
- Docker Desktop
- Git và GitHub
- Postman/Insomnia
- VirtualBox/VMware
```

#### Cloud Accounts
- AWS Free Tier account
- Azure Free account
- Google Cloud Free tier
- GitHub Student Pack

### 📚 Learning Resources

#### Free Resources (Tháng 1-3)
- **TryHackMe**: Free rooms và pathways
- **OverTheWire**: Wargames cho beginners
- **YouTube**: NetworkChuck, John Hammond, LiveOverflow
- **Books**: Linux Command Line, Automate Boring Stuff
- **Documentation**: OWASP, NIST, vendor docs

#### Premium Resources (Tháng 4-12)
- **Platforms** ($30-50/month):
  - HackTheBox Academy
  - PentesterLab Pro
  - Cloud provider credits
  
- **Certifications** ($300-500 each):
  - CompTIA Security+/CySA+
  - eJPT/OSCP
  - AWS/Azure Security

- **Conferences** ($100-500):
  - BSides (local, often free)
  - Virtual conferences
  - Professional meetups

### 🤝 Community & Networking

#### Online Communities
- **Discord**: TryHackMe, HackTheBox, OSCP study groups
- **Reddit**: r/cybersecurity, r/netsec, r/AskNetsec
- **LinkedIn**: Professional networking
- **Twitter/X**: Follow security researchers
- **Slack**: Local security groups

#### Local Communities
- **Meetups**: OWASP chapters, BSides local
- **University**: Security clubs, ACM chapters
- **Professional**: ISC2, ISACA local chapters
- **Conferences**: Regional security conferences

---

## 💰 BUDGET PLANNING

### 🎓 Student Budget (Minimal)

#### Phase 1 (Tháng 1-3): $0-50
- **Free resources**: TryHackMe, YouTube, documentation
- **Equipment**: Use existing laptop, free VM software
- **Optional**: Domain cho blog ($15/year)

#### Phase 2 (Tháng 4-6): $50-150
- **Platforms**: HackTheBox Student ($8/month)
- **Cloud**: AWS/Azure credits ($20/month)
- **Books**: Used textbooks ($50)

#### Phase 3 (Tháng 7-9): $150-400
- **Certification**: Security+ ($370)
- **Conference**: BSides registration ($50)
- **Tools**: Burp Suite Pro student discount

#### Phase 4 (Tháng 10-12): $200-600
- **Advanced cert**: OSCP ($1,500 - có thể defer)
- **Professional tools**: ($100-200)
- **Networking events**: ($100-200)

### 💼 Professional Investment

#### Total Investment Target: $1,000-2,500 first year
#### Expected ROI: $30,000-50,000 salary increase
#### Break-even time: 2-3 months trong new role

---

## 🎯 SUCCESS STORIES & CAREER PATHS

### 📊 Realistic Timeline Expectations

#### 🟢 Fast Track (High Dedication - 25+ hrs/week)
- **Month 6**: First security role (internship/entry-level)
- **Month 12**: Mid-level position hoặc specialization
- **Year 2**: Senior position consideration

#### 🟡 Standard Track (Medium Dedication - 15-20 hrs/week)  
- **Month 9**: Entry-level position
- **Month 18**: Promotion to intermediate level
- **Year 3**: Senior position readiness

#### 🔴 Slow Track (Low Dedication - 5-10 hrs/week)
- **Month 12**: Basic competency
- **Year 2**: Entry-level readiness  
- **Year 4**: Professional competency

### 🏆 Sample Career Progressions

#### Path 1: SOC Analyst → Threat Hunter
```
Timeline: 18 months
Month 1-6: Foundation + Blue team focus
Month 7-12: SOC Analyst role
Month 13-18: Threat hunting specialization
Salary progression: $55k → $70k → $85k
```

#### Path 2: Junior Pentester → Senior Consultant
```
Timeline: 24 months  
Month 1-9: Foundation + Red team focus
Month 10-15: Junior Pentester role
Month 16-24: Senior consultant level
Salary progression: $65k → $85k → $110k
```

#### Path 3: Cloud Engineer → Cloud Security Architect
```
Timeline: 30 months
Month 1-12: Foundation + Cloud specialization
Month 13-24: Cloud Security Engineer
Month 25-30: Security Architect level
Salary progression: $75k → $95k → $130k
```

---

## 🚨 CRITICAL SUCCESS FACTORS

### ✅ Must-Do Actions
1. **Daily Practice**: Consistency beats intensity
2. **Document Everything**: Build portfolio từ day 1
3. **Network Actively**: Relationships = Opportunities
4. **Stay Current**: Technology evolves rapidly
5. **Give Back**: Teach others, contribute to community

### ❌ Common Pitfalls to Avoid
1. **Tutorial Hell**: Balance learning với practice
2. **Certification Chasing**: Skills > certificates
3. **Working in Isolation**: Community is crucial
4. **Perfectionism**: Start before you feel ready
5. **Narrow Focus**: Stay broad initially

### 🎯 Final Recommendations

#### For Maximum Success:
1. **Choose 1 specialization** sau khi complete foundation
2. **Build portfolio** parallel với learning
3. **Network early** và consistently
4. **Apply early** - experience > perfect readiness
5. **Stay ethical** - reputation is everything

#### Expected Outcomes:
- **Month 6**: Confident trong basic security concepts
- **Month 12**: Ready cho entry-level positions
- **Month 18**: Competitive cho mid-level roles
- **Month 24**: Specialization expertise achieved

---

**🎓 Remember**: Cybersecurity là một journey, không phải destination. Success comes from consistent effort, continuous learning, và community engagement.

**⏰ Time to Start**: The best time to start was yesterday. The second best time is NOW!

---

**Document Version**: 1.0.0  
**Created**: September 2025  
**Purpose**: Comprehensive roadmap for cybersecurity career development  
**Next Review**: December 2025  

📧 **Questions?** Join our community Discord hoặc reach out for guidance!

🚀 **Ready to Begin?** Start với Module 1.1 tomorrow morning!