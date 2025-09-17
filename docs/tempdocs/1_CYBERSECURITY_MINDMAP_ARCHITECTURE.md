# 🧠 KIẾN TRÚC MINDMAP CYBERSECURITY CHO SINH VIÊN IT

## 🎯 TỔNG QUAN CẤU TRÚC

```
                            🛡️ CYBERSECURITY MASTERY
                                        │
           ┌────────────┬────────────┬───┴───┬────────────┬────────────┐
           │            │            │       │            │            │
    1.💻 FOUNDATION  2.🔒 CORE    3.☁️ SERVICES 4.📊 MANAGEMENT 5.🚀 EXPERT 6.🤝 SOFT SKILLS
       (Nền tảng)   (Cốt lõi)    (Dịch vụ)   (Quản lý)    (Chuyên sâu)  (Kỹ năng mềm)
     [2-3 tháng]   [4-5 tháng]  [2-3 tháng] [2-3 tháng]  [3-4 tháng]   [Thường xuyên]
       CRITICAL      CRITICAL      HIGH       MEDIUM       OPTIONAL      HIGH
```

---

## 📚 1. FOUNDATION - NỀN TẢNG CNTT ⭐⭐⭐
*Thời gian: 2-3 tháng | Độ ưu tiên: CRITICAL*

### 1.1 🖥️ Computer Science Fundamentals
```
1.1 Computer Science
├── 1.1.1 🔧 Computer Architecture [HIGH]
│   ├── CPU, Memory, Storage systems
│   ├── Binary & Hexadecimal operations
│   ├── Assembly basics
│   └── Performance optimization
│
├── 1.1.2 💾 Operating Systems [CRITICAL] ⭐
│   ├── Process & Thread management
│   ├── Memory management & Virtual memory
│   ├── File systems (ext4, NTFS, APFS)
│   ├── System calls & APIs
│   └── Kernel concepts
│
└── 1.1.3 📊 Data Structures & Algorithms [HIGH]
    ├── Arrays, Linked Lists, Trees, Graphs
    ├── Sorting algorithms (Quick, Merge, Heap)
    ├── Searching algorithms & Hash tables
    ├── Big O notation
    └── 🔐 Cryptographic algorithms
```

### 1.2 🌐 Networking Foundation [CRITICAL] ⭐⭐⭐
```
1.2 Network Fundamentals
├── 1.2.1 📡 OSI & TCP/IP Models [CRITICAL]
│   ├── Layer 1-2: Physical & Data Link
│   ├── Layer 3: Network (IP, ICMP, OSPF)
│   ├── Layer 4: Transport (TCP, UDP, SCTP)
│   ├── Layer 5-7: Session, Presentation, Application
│   └── Protocol interactions & encapsulation
│
├── 1.2.2 🔗 Core Protocols [CRITICAL] ⭐
│   ├── HTTP/HTTPS & TLS handshake
│   ├── DNS, DHCP, ARP
│   ├── FTP, SSH, Telnet
│   ├── SMTP, POP3, IMAP
│   └── SNMP, LDAP, Kerberos
│
├── 1.2.3 🏗️ Network Infrastructure [HIGH]
│   ├── Routers, Switches, Hubs
│   ├── Firewalls, Load Balancers
│   ├── IDS/IPS systems
│   ├── Proxy servers, VPN gateways
│   └── SD-WAN & Network automation
│
└── 1.2.4 🏢 Network Architecture [HIGH]
    ├── LAN, WAN, MAN topologies
    ├── VLAN configuration & management
    ├── Subnetting & CIDR notation
    ├── NAT, PAT, Port forwarding
    └── IPv4 vs IPv6 transition
```

### 1.3 🐧 Operating Systems Mastery [CRITICAL] ⭐⭐
```
1.3 OS Administration
├── 1.3.1 🐧 Linux Expert [CRITICAL] ⭐⭐⭐
│   ├── File system hierarchy (/bin, /etc, /var)
│   ├── User & permission management (chmod, chown)
│   ├── Package management (apt, yum, dnf)
│   ├── Service management (systemctl, systemd)
│   ├── Shell scripting (Bash, Zsh)
│   ├── Process monitoring (ps, top, htop)
│   ├── Network tools (netstat, ss, tcpdump)
│   └── Log management (/var/log, journalctl)
│
├── 1.3.2 🪟 Windows Administration [HIGH]
│   ├── Active Directory fundamentals
│   ├── Group Policy Objects (GPO)
│   ├── PowerShell scripting
│   ├── Registry management
│   ├── Windows services & scheduled tasks
│   ├── Event logs & Windows logs
│   └── WSUS & patch management
│
└── 1.3.3 📦 Containerization [HIGH] ⭐
    ├── Docker fundamentals & best practices
    ├── Container images & Dockerfiles
    ├── Docker Compose & networking
    ├── Kubernetes basics (pods, services)
    ├── Container security scanning
    └── Registry management
```

### 1.4 🐍 Programming & Automation [CRITICAL] ⭐⭐
```
1.4 Development Skills
├── 1.4.1 🐍 Python for Security [CRITICAL] ⭐⭐⭐
│   ├── Core Python (syntax, OOP, modules)
│   ├── Network programming (sockets, requests)
│   ├── Web scraping (BeautifulSoup, Scrapy)
│   ├── Security libraries (Scapy, Nmap, Paramiko)
│   ├── API interactions & automation
│   └── Data analysis (pandas, numpy)
│
├── 1.4.2 💻 Shell Scripting [HIGH] ⭐
│   ├── Bash scripting mastery
│   ├── PowerShell for Windows
│   ├── One-liners & command chaining
│   ├── Regular expressions
│   └── Cron jobs & Task scheduler
│
├── 1.4.3 🌐 Web Technologies [HIGH]
│   ├── HTML5, CSS3, JavaScript ES6+
│   ├── REST APIs & GraphQL
│   ├── JSON, XML data formats
│   ├── WebSockets & real-time communication
│   └── Browser security models
│
└── 1.4.4 🗄️ Database Essentials [MEDIUM]
    ├── SQL basics (SELECT, JOIN, subqueries)
    ├── NoSQL concepts (MongoDB, Redis)
    ├── Database security & injection
    ├── Query optimization
    └── Backup & recovery
```

### 1.5 ☁️ Cloud Computing Foundation [HIGH] ⭐
```
1.5 Cloud Fundamentals
├── 1.5.1 ☁️ Service Models [HIGH]
│   ├── IaaS (Infrastructure as a Service)
│   ├── PaaS (Platform as a Service)
│   ├── SaaS (Software as a Service)
│   ├── FaaS (Function as a Service)
│   └── Multi-cloud strategies
│
├── 1.5.2 🏢 Major Providers [HIGH] ⭐
│   ├── AWS fundamentals (EC2, S3, VPC)
│   ├── Azure basics (VMs, Storage, VNet)
│   ├── Google Cloud Platform essentials
│   ├── Cloud pricing models
│   └── Hybrid cloud architectures
│
└── 1.5.3 🚀 Cloud-Native Technologies [MEDIUM]
    ├── Microservices architecture
    ├── Serverless computing (Lambda, Functions)
    ├── API gateways & service mesh
    ├── Infrastructure as Code (Terraform)
    └── Container orchestration (K8s)
```

---

## 🔒 2. SECURITY CORE - CỐT LÕI BẢO MẬT ⭐⭐⭐
*Thời gian: 4-5 tháng | Độ ưu tiên: CRITICAL*

### 2.1 🛡️ Security Fundamentals [CRITICAL] ⭐⭐⭐
```
2.1 Core Principles
├── 2.1.1 🔐 CIA Triad+ [CRITICAL]
│   ├── Confidentiality (Encryption, Access control)
│   ├── Integrity (Hash functions, Digital signatures)
│   ├── Availability (Redundancy, DDoS protection)
│   ├── Non-repudiation (Digital certificates)
│   ├── Authentication (MFA, Biometrics)
│   └── Authorization (RBAC, ABAC)
│
├── 2.1.2 📋 Security Models [HIGH]
│   ├── Bell-LaPadula (Confidentiality)
│   ├── Biba Model (Integrity)
│   ├── Clark-Wilson (Commercial integrity)
│   ├── Chinese Wall (Conflict of interest)
│   └── RBAC, DAC, MAC models
│
├── 2.1.3 ⚔️ Threat Landscape [CRITICAL] ⭐
│   ├── Threat actors (APT, Nation-state, Criminals)
│   ├── Attack vectors & surfaces
│   ├── Cyber Kill Chain
│   ├── MITRE ATT&CK Framework
│   └── Threat intelligence feeds
│
└── 2.1.4 🎯 Risk Assessment [HIGH]
    ├── Asset identification & valuation
    ├── Vulnerability assessment
    ├── Threat modeling (STRIDE, PASTA)
    ├── Risk calculation (ALE, SLE)
    └── Risk treatment strategies
```

### 2.2 🔐 Cryptography [CRITICAL] ⭐⭐
```
2.2 Cryptographic Systems
├── 2.2.1 🔑 Symmetric Encryption [CRITICAL]
│   ├── DES, 3DES (legacy)
│   ├── AES (128, 192, 256-bit)
│   ├── Stream ciphers (ChaCha20)
│   ├── Block cipher modes (ECB, CBC, GCM)
│   └── Key management & rotation
│
├── 2.2.2 🗝️ Asymmetric Encryption [CRITICAL]
│   ├── RSA algorithm & key sizes
│   ├── Elliptic Curve Cryptography (ECC)
│   ├── Diffie-Hellman key exchange
│   ├── Digital signatures (DSA, ECDSA)
│   └── Perfect Forward Secrecy
│
├── 2.2.3 #️⃣ Hash Functions [CRITICAL] ⭐
│   ├── MD5 (deprecated), SHA-1 (deprecated)
│   ├── SHA-2 family (256, 384, 512)
│   ├── SHA-3 (Keccak)
│   ├── bcrypt, scrypt, Argon2
│   ├── HMAC & PBKDF2
│   └── Hash collision attacks
│
└── 2.2.4 📜 PKI & Certificates [HIGH]
    ├── Certificate Authorities (CA)
    ├── X.509 certificate structure
    ├── SSL/TLS protocols (1.2, 1.3)
    ├── Certificate validation & pinning
    ├── OCSP & CRL
    └── Certificate transparency
```

### 2.3 🌐 Application Security [CRITICAL] ⭐⭐⭐
```
2.3 App Security
├── 2.3.1 🕸️ Web Application Security [CRITICAL] ⭐⭐⭐
│   ├── 🔝 OWASP Top 10 (2023) [CRITICAL]
│   │   ├── A01: Broken Access Control
│   │   ├── A02: Cryptographic Failures
│   │   ├── A03: Injection (SQL, NoSQL, LDAP)
│   │   ├── A04: Insecure Design
│   │   ├── A05: Security Misconfiguration
│   │   ├── A06: Vulnerable Components
│   │   ├── A07: Authentication Failures
│   │   ├── A08: Software/Data Integrity
│   │   ├── A09: Logging/Monitoring Failures
│   │   └── A10: Server-Side Request Forgery
│   │
│   ├── Secure coding practices
│   ├── Input validation & sanitization
│   ├── Output encoding & escaping
│   ├── Session management
│   ├── CSRF protection
│   └── Security headers (CSP, HSTS)
│
├── 2.3.2 🔌 API Security [HIGH] ⭐
│   ├── REST API security patterns
│   ├── GraphQL security considerations
│   ├── OAuth 2.0, OpenID Connect
│   ├── JWT security & best practices
│   ├── Rate limiting & throttling
│   └── API gateway security
│
├── 2.3.3 📱 Mobile Security [MEDIUM]
│   ├── iOS security architecture
│   ├── Android security model
│   ├── Mobile app penetration testing
│   ├── OWASP Mobile Top 10
│   ├── Certificate pinning
│   └── Mobile device management
│
└── 2.3.4 💻 Software Security [HIGH]
    ├── SAST (Static Analysis Security Testing)
    ├── DAST (Dynamic Application Security Testing)
    ├── IAST (Interactive Application Security Testing)
    ├── SCA (Software Composition Analysis)
    ├── Code review methodologies
    └── Secure SDLC integration
```

### 2.4 🌐 Network Security [CRITICAL] ⭐⭐
```
2.4 Network Defense & Attack
├── 2.4.1 🛡️ Network Defense [CRITICAL] ⭐
│   ├── Firewalls (Stateful, Next-gen, WAF)
│   ├── IDS/IPS (Snort, Suricata, Zeek)
│   ├── Network segmentation & micro-segmentation
│   ├── VLAN isolation & DMZ design
│   ├── Zero Trust Network Architecture (ZTNA)
│   └── Network monitoring & analytics
│
├── 2.4.2 ⚔️ Network Attacks [HIGH] ⭐
│   ├── DoS/DDoS attacks & mitigation
│   ├── Man-in-the-Middle (MITM)
│   ├── ARP poisoning & spoofing
│   ├── DNS hijacking & cache poisoning
│   ├── BGP hijacking
│   └── Network reconnaissance
│
├── 2.4.3 📡 Wireless Security [MEDIUM]
│   ├── Wi-Fi security (WEP, WPA, WPA2, WPA3)
│   ├── Evil Twin & Rogue AP attacks
│   ├── WPS attacks
│   ├── Bluetooth security vulnerabilities
│   └── Radio frequency (RF) attacks
│
└── 2.4.4 🔗 VPN & Tunneling [HIGH]
    ├── IPSec VPN protocols
    ├── OpenVPN & WireGuard
    ├── SSH tunneling techniques
    ├── SSL VPN solutions
    ├── SD-WAN security
    └── VPN vulnerabilities
```

### 2.5 🔴 Offensive Security [HIGH] ⭐⭐
```
2.5 Red Team Operations
├── 2.5.1 🎯 Penetration Testing [HIGH] ⭐⭐
│   ├── 🔍 Reconnaissance (OSINT, Social media)
│   ├── 🔍 Scanning & Enumeration (Nmap, Masscan)
│   ├── 💥 Exploitation (Metasploit, Custom exploits)
│   ├── 🏃 Post-exploitation & Privilege escalation
│   ├── 🌐 Lateral movement
│   ├── 💾 Data exfiltration
│   └── 📋 Reporting & remediation
│
├── 2.5.2 🔍 Vulnerability Assessment [HIGH]
│   ├── Automated scanning (Nessus, OpenVAS)
│   ├── CVSS scoring & prioritization
│   ├── Risk assessment methodologies
│   ├── Patch management strategies
│   └── Vulnerability databases (NVD, CVE)
│
├── 2.5.3 🚩 Red Team Operations [MEDIUM]
│   ├── Social engineering attacks
│   ├── Physical security testing
│   ├── C2 frameworks (Cobalt Strike, Empire)
│   ├── Persistence techniques
│   ├── Anti-forensics & evasion
│   └── Adversary simulation
│
└── 2.5.4 💻 Exploitation Techniques [HIGH]
    ├── Buffer overflows (Stack, Heap)
    ├── Return-oriented programming (ROP)
    ├── SQL injection advanced techniques
    ├── Cross-site scripting (XSS) variants
    ├── Server-side template injection
    └── Deserialization attacks
```

### 2.6 🔵 Defensive Security [HIGH] ⭐⭐
```
2.6 Blue Team Operations  
├── 2.6.1 🏢 Security Operations Center [HIGH] ⭐⭐
│   ├── SOC tiers (L1, L2, L3)
│   ├── Alert triage & prioritization
│   ├── Incident response procedures
│   ├── Playbook development
│   ├── Security orchestration (SOAR)
│   └── Metrics & KPIs
│
├── 2.6.2 📊 SIEM & Log Management [HIGH] ⭐
│   ├── Splunk Enterprise Security
│   ├── ELK Stack (Elasticsearch, Logstash, Kibana)
│   ├── IBM QRadar, ArcSight
│   ├── Log correlation & analysis
│   ├── Use case development
│   └── Data retention policies
│
├── 2.6.3 🕵️ Threat Hunting [MEDIUM] ⭐
│   ├── Hypothesis-driven hunting
│   ├── IOC/IOA based hunting
│   ├── Behavioral analysis
│   ├── Hunt team operations
│   ├── Threat intelligence integration
│   └── Hunt platform tools
│
└── 2.6.4 🔬 Digital Forensics [MEDIUM]
    ├── Disk forensics (EnCase, FTK)
    ├── Memory forensics (Volatility)
    ├── Network forensics (Wireshark, tcpdump)
    ├── Mobile forensics (Cellebrite, MSAB)
    ├── Cloud forensics
    └── Chain of custody procedures
```

---

## 🛠️ 3. SECURITY SERVICES - DỊCH VỤ BẢO MẬT ⭐⭐
*Thời gian: 2-3 tháng | Độ ưu tiên: HIGH*

### 3.1 ☁️ Cloud Security Services [HIGH] ⭐
```
3.1 Cloud Security
├── 3.1.1 ☁️ AWS Security Services [HIGH] ⭐
│   ├── IAM (Identity & Access Management)
│   ├── VPC Security Groups & NACLs
│   ├── AWS WAF & Shield (DDoS protection)
│   ├── CloudTrail & CloudWatch
│   ├── GuardDuty & Security Hub
│   ├── KMS (Key Management Service)
│   └── AWS Config & Systems Manager
│
├── 3.1.2 ☁️ Azure Security Services [HIGH]
│   ├── Azure Active Directory (AAD)
│   ├── Azure Sentinel (SIEM)
│   ├── Azure Security Center
│   ├── Key Vault & managed identities
│   ├── Application Gateway & Firewall
│   └── Azure Monitor & Log Analytics
│
├── 3.1.3 ☁️ GCP Security Services [MEDIUM]
│   ├── Cloud IAM & Resource Manager
│   ├── Cloud Security Command Center
│   ├── VPC Security & Cloud Armor
│   ├── Cloud KMS & Secret Manager
│   └── Chronicle Security Analytics
│
└── 3.1.4 🏢 Multi-Cloud Security [MEDIUM]
    ├── CSPM (Cloud Security Posture Management)
    ├── CWPP (Cloud Workload Protection Platform)
    ├── CASB (Cloud Access Security Broker)
    ├── Cloud compliance frameworks
    └── Multi-cloud governance
```

### 3.2 🔐 Identity & Access Management [HIGH] ⭐
```
3.2 IAM Systems
├── 3.2.1 🔑 Authentication Methods [HIGH]
│   ├── Multi-factor authentication (MFA)
│   ├── Biometric authentication
│   ├── Certificate-based authentication
│   ├── Passwordless authentication
│   └── Risk-based authentication
│
├── 3.2.2 🎫 Authorization & Access Control [HIGH]
│   ├── RBAC (Role-Based Access Control)
│   ├── ABAC (Attribute-Based Access Control)
│   ├── MAC & DAC models
│   ├── Least privilege principle
│   ├── Just-in-time access
│   └── Privileged Access Management (PAM)
│
└── 3.2.3 🤝 Identity Federation [MEDIUM]
    ├── SAML 2.0 authentication
    ├── OAuth 2.0 & OpenID Connect
    ├── Single Sign-On (SSO) solutions
    ├── Directory services integration
    └── Cross-domain identity management
```

### 3.3 🧪 Security Testing Services [HIGH]
```
3.3 Security Assessment
├── 3.3.1 🎯 Penetration Testing Services [HIGH]
│   ├── Web application penetration testing
│   ├── Network infrastructure testing
│   ├── Mobile application testing
│   ├── Cloud penetration testing
│   ├── Social engineering assessments
│   └── Red team exercises
│
├── 3.3.2 📊 Security Assessments [MEDIUM]
│   ├── Risk assessment & analysis
│   ├── Compliance audits (SOC 2, ISO 27001)
│   ├── Security architecture reviews
│   ├── Code security reviews
│   └── Third-party risk assessments
│
└── 3.3.3 🐛 Bug Bounty Programs [MEDIUM]
    ├── Platform management (HackerOne, Bugcrowd)
    ├── Scope definition & rules of engagement
    ├── Triage & validation processes
    ├── Researcher relations
    └── Vulnerability disclosure programs
```

### 3.4 🏢 Managed Security Services [MEDIUM]
```
3.4 Outsourced Security
├── 3.4.1 🔍 MDR (Managed Detection & Response) [MEDIUM]
│   ├── 24/7 security monitoring
│   ├── Threat detection & analysis
│   ├── Incident response services
│   ├── Threat hunting services
│   └── Forensics investigation
│
├── 3.4.2 🛡️ MSSP (Managed Security Service Provider) [MEDIUM]
│   ├── Firewall management
│   ├── SIEM management & monitoring
│   ├── Vulnerability management
│   ├── Compliance management
│   └── Security device monitoring
│
└── 3.4.3 🚨 Incident Response Services [MEDIUM]
    ├── Emergency response retainer
    ├── Incident containment & eradication
    ├── Forensics & evidence collection
    ├── Recovery & lessons learned
    └── Legal & regulatory support
```

---

## 📊 4. SECURITY MANAGEMENT - QUẢN LÝ BẢO MẬT ⭐
*Thời gian: 2-3 tháng | Độ ưu tiên: MEDIUM-HIGH*

### 4.1 ⚖️ Risk Management [MEDIUM-HIGH]
```
4.1 Risk Framework
├── 4.1.1 📊 Risk Assessment [HIGH]
│   ├── Asset identification & classification
│   ├── Threat modeling & analysis
│   ├── Vulnerability assessment
│   ├── Risk calculation (Qualitative/Quantitative)
│   ├── Risk matrices & heat maps
│   └── Risk appetite & tolerance
│
├── 4.1.2 🎯 Risk Treatment [HIGH]
│   ├── Risk acceptance strategies
│   ├── Risk mitigation controls
│   ├── Risk transfer (Insurance, outsourcing)
│   ├── Risk avoidance measures
│   └── Residual risk management
│
└── 4.1.3 🔄 Business Continuity [MEDIUM]
    ├── Business Impact Analysis (BIA)
    ├── Business Continuity Planning (BCP)
    ├── Disaster Recovery Planning (DRP)
    ├── RTO & RPO requirements
    ├── Testing & exercises
    └── Crisis management
```

### 4.2 📋 Compliance & Governance [MEDIUM]
```
4.2 Regulatory Framework
├── 4.2.1 📜 Regulatory Compliance [MEDIUM]
│   ├── GDPR (General Data Protection Regulation)
│   ├── CCPA (California Consumer Privacy Act)
│   ├── HIPAA (Healthcare)
│   ├── PCI DSS (Payment Card Industry)
│   ├── SOX (Sarbanes-Oxley)
│   └── Industry-specific regulations
│
├── 4.2.2 📊 Standards & Frameworks [MEDIUM]
│   ├── ISO 27001/27002 (Information Security)
│   ├── NIST Cybersecurity Framework
│   ├── CIS Controls (Critical Security Controls)
│   ├── COBIT (Control Objectives)
│   └── FAIR (Factor Analysis of Information Risk)
│
└── 4.2.3 🔍 Audit & Assurance [MEDIUM]
    ├── Internal audit programs
    ├── External audit coordination
    ├── Gap analysis & remediation
    ├── Control testing & validation
    └── Audit trail management
```

### 4.3 🎯 Security Program Management [MEDIUM]
```
4.3 Program Development
├── 4.3.1 📈 Security Strategy [MEDIUM]
│   ├── Vision & mission development
│   ├── Security roadmap & planning
│   ├── Budget planning & allocation
│   ├── Resource management
│   └── Executive communication
│
├── 4.3.2 📜 Policy Development [MEDIUM]
│   ├── Security policy framework
│   ├── Standards & procedures
│   ├── Guidelines & best practices
│   ├── Policy enforcement
│   └── Policy lifecycle management
│
├── 4.3.3 📊 Security Metrics [MEDIUM]
│   ├── KPIs & KRIs development
│   ├── Security dashboards
│   ├── Maturity assessments
│   ├── Benchmarking studies
│   └── ROI/ROSI calculations
│
└── 4.3.4 🤝 Vendor Management [MEDIUM]
    ├── Third-party risk assessment
    ├── Vendor security assessments
    ├── Contract security requirements
    ├── Supply chain security
    └── Vendor monitoring
```

### 4.4 🎓 Security Awareness & Training [MEDIUM]
```
4.4 Human Factor Security
├── 4.4.1 📢 Awareness Programs [MEDIUM]
│   ├── Phishing simulation campaigns
│   ├── Security newsletters & communications
│   ├── Posters & awareness campaigns
│   ├── Gamification & competitions
│   └── Security culture development
│
├── 4.4.2 👥 Role-Based Training [MEDIUM]
│   ├── Executive security briefings
│   ├── Developer security training
│   ├── End-user security education
│   ├── IT staff specialized training
│   └── Contractor security training
│
└── 4.4.3 🏆 Security Culture [MEDIUM]
    ├── Security champion programs
    ├── Security by design principles
    ├── Incident learning programs
    ├── Recognition & reward programs
    └── Continuous improvement
```

---

## 🚀 5. ADVANCED SPECIALIZATIONS - CHUYÊN MÔN SÂU ⭐
*Thời gian: 3-4 tháng | Độ ưu tiên: OPTIONAL*

### 5.1 🤖 AI/ML Security [SPECIALIZED] 🔥⭐
```
5.1 AI Security
├── 5.1.1 ⚔️ AI Attack Vectors [HIGH]
│   ├── Adversarial examples & attacks
│   ├── Model poisoning & backdoors
│   ├── Model extraction & stealing
│   ├── Privacy attacks (Membership inference)
│   ├── Data poisoning attacks
│   └── Model inversion attacks
│
├── 5.1.2 🛡️ Securing AI Systems [HIGH]
│   ├── Secure ML pipeline design
│   ├── Model security testing
│   ├── Differential privacy techniques
│   ├── Federated learning security
│   ├── Adversarial training
│   └── AI governance frameworks
│
├── 5.1.3 🧠 LLM Security [NEW] 🔥
│   ├── Prompt injection attacks
│   ├── Jailbreaking techniques
│   ├── Data leakage prevention
│   ├── Hallucination risks
│   ├── Model alignment issues
│   └── AI red teaming
│
└── 5.1.4 🔬 AI Security Research [ADVANCED]
    ├── Novel attack development
    ├── Defense mechanism research
    ├── AI ethics & bias detection
    ├── Quantum ML security
    └── Academic publications
```

### 5.2 🏭 IoT & Operational Technology Security [SPECIALIZED]
```
5.2 IoT/OT Security
├── 5.2.1 📡 IoT Security [MEDIUM]
│   ├── IoT device security assessment
│   ├── Communication protocol security
│   ├── Firmware analysis & reverse engineering
│   ├── IoT network security
│   └── IoT forensics
│
├── 5.2.2 🏭 Industrial Control Systems [MEDIUM]
│   ├── SCADA system security
│   ├── PLC (Programmable Logic Controller) security
│   ├── HMI (Human Machine Interface) security
│   ├── Industrial protocols (Modbus, DNP3)
│   └── Safety instrumented systems
│
└── 5.2.3 🏙️ Critical Infrastructure [SPECIALIZED]
    ├── Energy sector security
    ├── Manufacturing systems
    ├── Healthcare IoT security
    ├── Smart cities infrastructure
    └── Transportation systems
```

### 5.3 ⛓️ Blockchain & Web3 Security [SPECIALIZED] 🔥
```
5.3 Blockchain Security
├── 5.3.1 ⛓️ Blockchain Core Security [MEDIUM]
│   ├── Consensus mechanism vulnerabilities
│   ├── 51% attacks & prevention
│   ├── Fork attacks & solutions
│   ├── Network-level attacks
│   └── Wallet security
│
├── 5.3.2 📝 Smart Contract Security [HIGH]
│   ├── Solidity security patterns
│   ├── Reentrancy attacks
│   ├── Integer overflow/underflow
│   ├── Access control vulnerabilities
│   ├── Contract auditing methodologies
│   └── Formal verification
│
└── 5.3.3 💰 DeFi Security [HIGH]
    ├── Flash loan attacks
    ├── Oracle manipulation
    ├── MEV (Maximal Extractable Value)
    ├── Cross-chain bridge security
    └── Governance attacks
```

### 5.4 🔄 DevSecOps [SPECIALIZED] 🔥⭐
```
5.4 DevSecOps Pipeline
├── 5.4.1 🔄 CI/CD Security [HIGH] ⭐
│   ├── Pipeline security design
│   ├── Secret management (Vault, K8s secrets)
│   ├── Artifact signing & verification
│   ├── Supply chain security
│   ├── SBOM (Software Bill of Materials)
│   └── Dependency scanning
│
├── 5.4.2 🏗️ Infrastructure as Code [HIGH]
│   ├── Terraform security best practices
│   ├── CloudFormation security
│   ├── Policy as Code (OPA, Rego)
│   ├── Compliance as Code
│   └── Configuration drift detection
│
├── 5.4.3 📦 Container & K8s Security [HIGH] ⭐
│   ├── Container image security scanning
│   ├── Runtime protection (Falco, Twistlock)
│   ├── Kubernetes network policies
│   ├── RBAC configuration
│   ├── Service mesh security (Istio)
│   ├── Pod security standards
│   └── Admission controllers
│
└── 5.4.4 🤖 Security Automation [MEDIUM]
    ├── SOAR platform integration
    ├── Security orchestration workflows
    ├── Automated incident response
    ├── ChatOps security integration
    └── Security testing automation
```

### 5.5 🦠 Malware Analysis & Reverse Engineering [SPECIALIZED]
```
5.5 Malware Research
├── 5.5.1 🔍 Static Analysis [MEDIUM]
│   ├── PE/ELF file analysis
│   ├── Disassembly (IDA Pro, Ghidra)
│   ├── Decompilation techniques
│   ├── String & API analysis
│   └── Signature development
│
├── 5.5.2 🏃 Dynamic Analysis [MEDIUM]
│   ├── Sandbox analysis (Cuckoo, Joe Sandbox)
│   ├── Debugging (x64dbg, GDB, WinDbg)
│   ├── API monitoring & hooking
│   ├── Network behavior analysis
│   └── Memory forensics
│
├── 5.5.3 🔧 Advanced Techniques [ADVANCED]
│   ├── Unpacking & deobfuscation
│   ├── Anti-analysis bypass techniques
│   ├── Rootkit analysis
│   ├── Firmware reverse engineering
│   └── Mobile malware analysis
│
└── 5.5.4 🎯 Threat Intelligence [MEDIUM]
    ├── IOC (Indicators of Compromise) extraction
    ├── YARA rule development
    ├── Attribution techniques
    ├── TTP (Tactics, Techniques, Procedures) mapping
    └── Threat actor profiling
```

---

## 💼 6. SOFT SKILLS & CAREER - KỸ NĂNG MỀM ⭐⭐
*Thời gian: Ongoing | Độ ưu tiên: HIGH*

### 6.1 📝 Technical Communication [HIGH] ⭐
```
6.1 Communication Skills
├── 6.1.1 📄 Documentation Skills [HIGH]
│   ├── Technical writing excellence
│   ├── Security report writing
│   ├── Diagram creation (Visio, Lucidchart)
│   ├── Knowledge base development
│   └── Standard operating procedures
│
├── 6.1.2 🎤 Presentation Skills [HIGH]
│   ├── Executive security briefings
│   ├── Technical demonstrations
│   ├── Conference presentations
│   ├── Webinar delivery
│   └── Training session facilitation
│
└── 6.1.3 🎓 Teaching & Mentoring [MEDIUM]
    ├── Knowledge transfer techniques
    ├── Training program development
    ├── Mentorship programs
    ├── Content creation
    └── Community contributions
```

### 6.2 🎯 Professional Development [HIGH] ⭐
```
6.2 Career Growth
├── 6.2.1 🏆 Certification Roadmap [HIGH]
│   ├── Entry Level: CompTIA (Security+, Network+)
│   ├── Intermediate: CySA+, PenTest+, SSCP
│   ├── Advanced: OSCP, CISSP, CISM, SANS
│   ├── Expert: OSEP, OSEE, GSE, CISSP
│   └── Specialized: AWS Security, CKS, CISSP
│
├── 6.2.2 📈 Career Progression [HIGH]
│   ├── SOC Analyst → Senior Analyst → SOC Manager
│   ├── Pentester → Senior → Lead → Principal
│   ├── Security Engineer → Senior → Architect
│   ├── Security Analyst → Manager → Director → CISO
│   └── Consultant → Senior → Principal → Partner
│
└── 6.2.3 📚 Continuous Learning [HIGH]
    ├── Industry news & blogs
    ├── Research papers & whitepapers
    ├── Conference attendance
    ├── Online courses & MOOCs
    ├── Hands-on lab practice
    └── Community participation
```

### 6.3 💼 Business & Management Skills [MEDIUM] ⭐
```
6.3 Business Acumen
├── 6.3.1 📊 Project Management [MEDIUM]
│   ├── Agile/Scrum methodologies
│   ├── Risk management planning
│   ├── Resource allocation
│   ├── Stakeholder management
│   └── Timeline & budget management
│
├── 6.3.2 💰 Business Understanding [MEDIUM]
│   ├── Cost-benefit analysis
│   ├── ROI/ROSI calculations
│   ├── Business case development
│   ├── Executive communication
│   └── Budget planning & justification
│
└── 6.3.3 👑 Leadership Skills [MEDIUM]
    ├── Team building & management
    ├── Conflict resolution
    ├── Decision making processes
    ├── Strategic thinking
    ├── Change management
    └── Emotional intelligence
```

---

## 🎯 HỆ THỐNG ƯU TIÊN VÀ PHÂN CẤP

### ⭐⭐⭐ CRITICAL PRIORITIES (70% thời gian - Tháng 1-6)
1. **Linux Command Line** - Không thể thiếu
2. **Networking (TCP/IP)** - Nền tảng của mọi thứ
3. **Python for Security** - Automation & tool development
4. **OWASP Top 10** - Web security fundamentals
5. **Security Fundamentals** - CIA Triad, Risk, Threats

### ⭐⭐ HIGH PRIORITIES (20% thời gian - Tháng 4-9)
1. **Cloud Security (AWS/Azure)**
2. **SOC Operations & SIEM**
3. **Penetration Testing Basics**
4. **Container Security**
5. **DevSecOps Fundamentals**

### ⭐ MEDIUM-LOW PRIORITIES (10% thời gian - Tháng 10+)
1. **AI/ML Security** (Emerging field)
2. **Blockchain Security** (Specialized)
3. **IoT Security** (Niche market)
4. **Malware Analysis** (Highly specialized)
5. **Advanced Forensics** (Expert level)

---

## 🎓 LEARNING PATH RECOMMENDATIONS

### 👶 BEGINNER PATH (0-6 tháng)
```
Month 1-2: Foundation
- Linux basics
- Networking fundamentals
- Python programming

Month 3-4: Core Security
- Security fundamentals
- Web security (OWASP Top 10)
- Basic penetration testing

Month 5-6: Specialization Choice
- Cloud Security OR
- SOC Operations OR
- Web Application Security
```

### 🚀 INTERMEDIATE PATH (6-12 tháng)
```
Month 7-9: Deep Specialization
- Advanced skills in chosen area
- Certification preparation
- Real-world projects

Month 10-12: Professional Ready
- Portfolio development
- Advanced certifications
- Job interview preparation
```

### 💎 ADVANCED PATH (12+ tháng)
```
Year 2: Expert Development
- Research & development
- Advanced specializations
- Leadership & management
- Community contributions
```

---

## 📊 THANG ĐÁNH GIÁ SKILL LEVEL

### 🟢 LEVEL 1: BEGINNER (Tháng 1-3)
- [ ] Sử dụng thành thạo Linux command line
- [ ] Hiểu cơ bản về TCP/IP và networking
- [ ] Viết được Python scripts đơn giản
- [ ] Nhận biết được các lỗ hổng web cơ bản
- [ ] Sử dụng được Burp Suite proxy

### 🟡 LEVEL 2: INTERMEDIATE (Tháng 3-6)
- [ ] Exploit được các lỗ hổng web thông thường
- [ ] Thực hiện network scanning và enumeration
- [ ] Phân tích logs trong SIEM
- [ ] Viết security tools đơn giản
- [ ] Hoàn thành CTF challenges

### 🟠 LEVEL 3: ADVANCED (Tháng 6-12)
- [ ] Thực hiện penetration test hoàn chỉnh
- [ ] Xử lý incident security
- [ ] Thiết kế security architecture
- [ ] Phát triển exploits
- [ ] Dẫn dắt security projects

### 🔴 LEVEL 4: EXPERT (12+ tháng)
- [ ] Nghiên cứu & phát hiện vulnerabilities mới
- [ ] Thiết kế security programs
- [ ] Mentor và training team members
- [ ] Trình bày tại conferences
- [ ] Đóng góp cho security community

---

**🎯 MỤC TIÊU CUỐI CÙNG**: Trở thành Security Engineer/Specialist có thể làm việc tại các công ty công nghệ hàng đầu với mức lương $80k-150k/năm tại thị trường quốc tế.

**⏰ THỜI GIAN DỰ KIẾN**: 12-18 tháng học tập nghiêm túc với cam kết 15-20 giờ/tuần.

---

*"Cybersecurity is not a destination, it's a journey of continuous learning and adaptation."*

**Document Version**: 1.0.0  
**Created**: September 2025  
**Purpose**: Comprehensive mindmap architecture for cybersecurity learning