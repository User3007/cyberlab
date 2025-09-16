"""
Cyber Kill Chain Security Component
Advanced attack methodology framework - Enhanced with latest threat intelligence
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from typing import Dict, List, Any, Optional

# Import shared utilities
from ...shared.color_schemes import THEORY_CONCEPTS_COLORS
from ...shared.ui_components import create_banner, create_takeaways, create_info_card, create_cheat_sheet_tabs
from ...shared.diagram_utils import create_basic_figure, add_process_flow
from ...templates.component_template import ComponentTemplate


class CyberKillChainComponent(ComponentTemplate):
    """Cyber Kill Chain component with enhanced threat intelligence"""
    
    def __init__(self):
        super().__init__(
            component_name="⚔️ Cyber Kill Chain",
            description="Advanced attack methodology framework for understanding and defending against cyber threats",
            color_scheme=THEORY_CONCEPTS_COLORS,
            estimated_time="35 minutes"
        )
        
        self.set_prerequisites([
            "Basic cybersecurity concepts",
            "Understanding of network fundamentals", 
            "Familiarity with attack vectors"
        ])
        
        self.set_learning_objectives([
            "Master the 7 stages of Cyber Kill Chain",
            "Identify defensive opportunities at each stage",
            "Apply kill chain analysis to real-world attacks",
            "Develop comprehensive defense strategies",
            "Understand modern variations and adaptations"
        ])
        
        self.set_key_concepts([
            "Kill Chain Phases", "Attack Lifecycle", "Defense in Depth",
            "Threat Hunting", "Incident Response", "Attribution Analysis"
        ])
    
    def render_content(self):
        """Render the Cyber Kill Chain content"""
        
        # Kill chain overview
        self._render_kill_chain_overview()
        
        # Interactive kill chain stages
        self._render_interactive_stages()
        
        # Real-world case studies
        self._render_case_studies()
        
        # Defense strategies
        self._render_defense_strategies()
        
        # Modern adaptations
        self._render_modern_adaptations()
        
        # Cheat sheets
        self._render_cheat_sheets()
    
    def _render_kill_chain_overview(self):
        """Render Cyber Kill Chain overview"""
        st.subheader("⚔️ Cyber Kill Chain Framework")
        
        # Enhanced visual banner with latest context
        st.markdown("""
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 2rem; border-radius: 12px; margin-bottom: 1.5rem; color: white; text-align: center;">
            <h2 style="margin: 0 0 0.5rem 0;">🎯 Lockheed Martin Cyber Kill Chain®</h2>
            <p style="margin: 0; opacity: 0.9; font-size: 1.1rem;">
                Developed 2011 • Enhanced 2024 • Industry Standard Framework
            </p>
            <p style="margin: 0.5rem 0 0 0; opacity: 0.8; font-size: 0.9rem;">
                "Understanding adversary behavior to build better defenses"
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # Kill chain phases with modern context
        kill_chain_phases = [
            {
                "name": "1. Reconnaissance",
                "description": "Gather information about targets and infrastructure",
                "modern_techniques": ["OSINT", "Social Media Mining", "DNS Enumeration", "Dark Web Intelligence"],
                "detection_difficulty": "Low",
                "prevention_opportunity": "High"
            },
            {
                "name": "2. Weaponization", 
                "description": "Create malicious payloads and delivery mechanisms",
                "modern_techniques": ["Living off the Land", "Fileless Malware", "Supply Chain Attacks", "AI-Generated Payloads"],
                "detection_difficulty": "Very High",
                "prevention_opportunity": "Medium"
            },
            {
                "name": "3. Delivery",
                "description": "Transmit weapon to target environment",
                "modern_techniques": ["Spear Phishing", "Watering Holes", "USB Drops", "Cloud Storage Abuse"],
                "detection_difficulty": "Medium",
                "prevention_opportunity": "High"
            },
            {
                "name": "4. Exploitation",
                "description": "Execute code and exploit vulnerabilities",
                "modern_techniques": ["Zero-Days", "1-Click Exploits", "Browser Exploits", "Memory Corruption"],
                "detection_difficulty": "Medium",
                "prevention_opportunity": "Medium"
            },
            {
                "name": "5. Installation",
                "description": "Install persistent access mechanisms",
                "modern_techniques": ["Registry Persistence", "Scheduled Tasks", "WMI Events", "DLL Hijacking"],
                "detection_difficulty": "Low",
                "prevention_opportunity": "High"
            },
            {
                "name": "6. Command & Control",
                "description": "Establish communication channels",
                "modern_techniques": ["DNS Tunneling", "HTTPS Beaconing", "Social Media C2", "Blockchain C2"],
                "detection_difficulty": "Low",
                "prevention_opportunity": "Very High"
            },
            {
                "name": "7. Actions on Objectives",
                "description": "Execute mission objectives",
                "modern_techniques": ["Data Exfiltration", "Ransomware", "Lateral Movement", "Destruction"],
                "detection_difficulty": "Very Low",
                "prevention_opportunity": "Low"
            }
        ]
        
        # Create enhanced process flow visualization
        fig = create_basic_figure("Cyber Kill Chain Process Flow", self.color_scheme, height=400)
        fig = add_process_flow(fig, kill_chain_phases, self.color_scheme)
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Key statistics and insights
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Framework Age", "13+ Years", "Still Relevant")
        with col2:
            st.metric("Industry Adoption", "90%+", "Global Standard")
        with col3:
            st.metric("Attack Prevention", "Early Stages", "Most Effective")
        with col4:
            st.metric("Modern Variants", "10+", "Evolved Frameworks")
    
    def _render_interactive_stages(self):
        """Render interactive kill chain stages explorer"""
        st.subheader("🔍 Interactive Kill Chain Analysis")
        
        # Enhanced kill chain data with 2024 updates
        kill_chain_data = {
            "1. Reconnaissance": {
                "objective": "Gather intelligence on targets, infrastructure, and personnel",
                "attacker_activities": [
                    "OSINT collection from public sources",
                    "Social media profiling and mapping",
                    "DNS enumeration and subdomain discovery", 
                    "Employee information gathering",
                    "Technology stack identification",
                    "Physical site reconnaissance"
                ],
                "tools_techniques": {
                    "OSINT Tools": ["theHarvester", "Maltego", "Shodan", "Google Dorking"],
                    "Social Engineering": ["Social Media Mining", "LinkedIn Scraping", "Company Research"],
                    "Network Scanning": ["Nmap", "Masscan", "Zmap", "DNS Recon"],
                    "Modern AI Tools": ["ChatGPT for OSINT", "Automated Profiling", "Deepfake Reconnaissance"]
                },
                "defensive_measures": [
                    "Monitor external data exposure",
                    "Implement social media policies", 
                    "Use threat intelligence feeds",
                    "Deploy honeypots and canaries",
                    "Regular external attack surface assessment"
                ],
                "detection_methods": [
                    "External scanning detection",
                    "Honeypot interactions",
                    "Social media monitoring",
                    "Dark web monitoring"
                ],
                "real_examples": [
                    "APT1 extensive reconnaissance campaigns",
                    "Russian GRU targeting Olympic organizations",
                    "North Korean Lazarus Group financial reconnaissance"
                ]
            },
            "2. Weaponization": {
                "objective": "Create malicious payloads tailored to target environment",
                "attacker_activities": [
                    "Malware development and customization",
                    "Exploit kit preparation",
                    "Social engineering content creation",
                    "Infrastructure setup and testing",
                    "Anti-forensics implementation"
                ],
                "tools_techniques": {
                    "Malware Families": ["Cobalt Strike", "Metasploit", "Empire", "Custom RATs"],
                    "Exploit Kits": ["RIG EK", "Fallout EK", "GrandSoft EK"],
                    "Fileless Techniques": ["PowerShell Empire", "Living off the Land", "Memory-only Payloads"],
                    "AI-Enhanced": ["Automated Payload Generation", "Evasion Optimization", "Target-Specific Customization"]
                },
                "defensive_measures": [
                    "Threat intelligence sharing",
                    "Signature-based detection",
                    "Behavioral analysis",
                    "Supply chain security",
                    "Code signing verification"
                ],
                "detection_methods": [
                    "Static malware analysis",
                    "Dynamic sandbox analysis", 
                    "Threat intelligence correlation",
                    "Anomaly detection"
                ],
                "real_examples": [
                    "Stuxnet weapon development",
                    "NotPetya wiper customization",
                    "SolarWinds supply chain weaponization"
                ]
            },
            "3. Delivery": {
                "objective": "Transmit weaponized payload to target systems",
                "attacker_activities": [
                    "Email campaign execution",
                    "Watering hole attacks",
                    "Physical media deployment",
                    "Supply chain compromise",
                    "Cloud service abuse"
                ],
                "tools_techniques": {
                    "Email Delivery": ["Spear Phishing", "Business Email Compromise", "Attachment-based", "Link-based"],
                    "Web-based": ["Watering Holes", "Malvertising", "Drive-by Downloads", "SEO Poisoning"],
                    "Physical": ["USB Drops", "CD/DVD", "Hardware Implants", "Badge Cloning"],
                    "Modern Vectors": ["Cloud Storage Abuse", "Collaboration Tools", "Mobile Apps", "IoT Devices"]
                },
                "defensive_measures": [
                    "Email security gateways",
                    "Web filtering and proxies",
                    "User awareness training",
                    "Endpoint protection",
                    "Network segmentation"
                ],
                "detection_methods": [
                    "Email analysis and sandboxing",
                    "Web traffic monitoring",
                    "DNS monitoring",
                    "User behavior analytics"
                ],
                "real_examples": [
                    "Target Corp. point-of-sale malware",
                    "Ukrainian power grid spear phishing",
                    "COVID-19 themed phishing campaigns"
                ]
            },
            "4. Exploitation": {
                "objective": "Execute malicious code and gain initial system access",
                "attacker_activities": [
                    "Vulnerability exploitation",
                    "Privilege escalation attempts",
                    "Anti-analysis evasion",
                    "System fingerprinting",
                    "Initial payload execution"
                ],
                "tools_techniques": {
                    "Exploit Types": ["Buffer Overflows", "SQL Injection", "XSS", "CSRF"],
                    "Zero-Days": ["Browser Exploits", "OS Vulnerabilities", "Application Flaws"],
                    "Living off Land": ["PowerShell", "WMI", "CertUtil", "BITSAdmin"],
                    "Modern Techniques": ["Spectre/Meltdown", "Rowhammer", "Supply Chain Exploits"]
                },
                "defensive_measures": [
                    "Patch management",
                    "Application whitelisting",
                    "Exploit prevention",
                    "Runtime protection",
                    "Micro-segmentation"
                ],
                "detection_methods": [
                    "Exploit detection systems",
                    "Behavioral monitoring",
                    "Memory protection alerts",
                    "Anomaly detection"
                ],
                "real_examples": [
                    "EternalBlue exploitation (WannaCry)",
                    "BlueKeep vulnerability exploitation",
                    "Log4j exploitation campaigns"
                ]
            },
            "5. Installation": {
                "objective": "Establish persistent access and maintain presence",
                "attacker_activities": [
                    "Backdoor installation",
                    "Persistence mechanism creation",
                    "System modification",
                    "Credential harvesting",
                    "Defense evasion setup"
                ],
                "tools_techniques": {
                    "Persistence": ["Registry Keys", "Scheduled Tasks", "Services", "DLL Hijacking"],
                    "Backdoors": ["Web Shells", "Remote Access Tools", "Rootkits", "Bootkits"],
                    "Evasion": ["Process Hollowing", "DLL Injection", "Reflective Loading"],
                    "Modern Methods": ["WMI Events", "COM Hijacking", "Cloud Persistence", "Container Escape"]
                },
                "defensive_measures": [
                    "Host-based intrusion detection",
                    "File integrity monitoring",
                    "Registry monitoring",
                    "Behavioral analysis",
                    "Privilege restriction"
                ],
                "detection_methods": [
                    "Persistence scanning",
                    "Startup monitoring",
                    "File system monitoring",
                    "Process monitoring"
                ],
                "real_examples": [
                    "APT29 CozyBear persistence",
                    "Carbanak banking backdoors",
                    "Chinese APT infrastructure"
                ]
            },
            "6. Command & Control": {
                "objective": "Establish reliable communication channels with compromised systems",
                "attacker_activities": [
                    "C2 server communication",
                    "Command execution",
                    "Data staging and exfiltration prep",
                    "Additional tool deployment",
                    "Network reconnaissance"
                ],
                "tools_techniques": {
                    "C2 Protocols": ["HTTP/HTTPS", "DNS Tunneling", "ICMP", "Social Media APIs"],
                    "Infrastructure": ["Bulletproof Hosting", "Fast Flux", "Domain Generation", "CDN Abuse"],
                    "Evasion": ["Encrypted Channels", "Protocol Mimicry", "Traffic Blending"],
                    "Modern C2": ["Cloud Services", "Blockchain", "P2P Networks", "AI-Powered C2"]
                },
                "defensive_measures": [
                    "Network monitoring and analysis",
                    "DNS monitoring",
                    "Proxy/firewall rules",
                    "Threat intelligence feeds",
                    "Behavioral analytics"
                ],
                "detection_methods": [
                    "Network traffic analysis",
                    "DNS anomaly detection",
                    "Beacon detection",
                    "C2 infrastructure tracking"
                ],
                "real_examples": [
                    "Maze ransomware C2 infrastructure",
                    "APT40 maritime industry targeting",
                    "FIN7 restaurant chain campaigns"
                ]
            },
            "7. Actions on Objectives": {
                "objective": "Execute the primary mission goals and objectives",
                "attacker_activities": [
                    "Data collection and exfiltration",
                    "System destruction or encryption",
                    "Lateral movement expansion",
                    "Additional target compromise",
                    "Evidence destruction"
                ],
                "tools_techniques": {
                    "Data Theft": ["Database Dumps", "File Exfiltration", "Screen Capture", "Keylogging"],
                    "Destruction": ["Ransomware", "Wipers", "System Corruption", "Data Deletion"],
                    "Espionage": ["Long-term Monitoring", "Intellectual Property Theft", "State Secrets"],
                    "Modern Goals": ["Cryptocurrency Mining", "Cloud Resource Abuse", "Supply Chain Poisoning"]
                },
                "defensive_measures": [
                    "Data loss prevention",
                    "Backup and recovery",
                    "Network segmentation",
                    "Privilege management",
                    "Incident response"
                ],
                "detection_methods": [
                    "Data exfiltration monitoring",
                    "Unusual file access patterns",
                    "Large data transfers",
                    "Encryption activity monitoring"
                ],
                "real_examples": [
                    "Equifax data breach (143M records)",
                    "Colonial Pipeline ransomware",
                    "SolarWinds espionage campaign"
                ]
            }
        }
        
        # Interactive stage selector
        selected_stage = st.selectbox(
            "🔍 Select Kill Chain Stage to Explore:",
            list(kill_chain_data.keys()),
            help="Choose a stage to see detailed analysis, modern techniques, and defense strategies",
            key="kill_chain_stage_selector"
        )
        
        stage_info = kill_chain_data[selected_stage]
        
        # Enhanced stage display
        create_info_card(
            f"🎯 {selected_stage}",
            stage_info['objective'],
            card_type="primary",
            color_scheme=self.color_scheme
        )
        
        # Tabbed detailed information
        tab1, tab2, tab3, tab4 = st.tabs(["🔧 Techniques", "🛡️ Defenses", "🔍 Detection", "📚 Examples"])
        
        with tab1:
            st.markdown("#### Attacker Activities")
            for activity in stage_info['attacker_activities']:
                st.markdown(f"• {activity}")
            
            st.markdown("#### Tools & Techniques (2024 Updated)")
            for category, tools in stage_info['tools_techniques'].items():
                with st.expander(f"📁 {category}"):
                    for tool in tools:
                        st.markdown(f"• **{tool}**")
        
        with tab2:
            st.markdown("#### Defensive Measures")
            for measure in stage_info['defensive_measures']:
                st.markdown(f"🛡️ {measure}")
        
        with tab3:
            st.markdown("#### Detection Methods")
            for method in stage_info['detection_methods']:
                st.markdown(f"🔍 {method}")
        
        with tab4:
            st.markdown("#### Real-World Examples")
            for example in stage_info['real_examples']:
                st.markdown(f"📖 {example}")
    
    def _render_case_studies(self):
        """Render real-world case studies"""
        st.subheader("📚 Real-World Case Studies")
        
        case_studies = {
            "APT29 (Cozy Bear) - SolarWinds Attack": {
                "year": "2020-2021",
                "attribution": "Russian SVR",
                "target": "US Government & Fortune 500",
                "kill_chain_analysis": {
                    "Reconnaissance": "Extensive OSINT on SolarWinds customers and infrastructure",
                    "Weaponization": "Custom SUNBURST backdoor embedded in legitimate software",
                    "Delivery": "Software supply chain compromise via SolarWinds Orion updates",
                    "Exploitation": "Legitimate software update mechanism exploited",
                    "Installation": "SUNBURST backdoor with dormancy period and victim profiling",
                    "Command & Control": "Sophisticated C2 using legitimate domains and DNS",
                    "Actions on Objectives": "Long-term espionage, credential theft, lateral movement"
                },
                "impact": "18,000+ organizations affected, classified data stolen",
                "lessons": "Supply chain security, zero trust architecture, continuous monitoring"
            },
            "Lazarus Group - SWIFT Banking Attacks": {
                "year": "2016-2022",
                "attribution": "North Korean APT",
                "target": "Global Banking System",
                "kill_chain_analysis": {
                    "Reconnaissance": "Financial institution research, SWIFT network analysis",
                    "Weaponization": "Custom malware toolkit, living-off-the-land techniques",
                    "Delivery": "Spear phishing with financial themes, watering hole attacks",
                    "Exploitation": "Zero-day exploits, social engineering of bank employees",
                    "Installation": "Persistent backdoors, credential harvesting tools",
                    "Command & Control": "Multi-stage C2 with proxy networks and encrypted channels",
                    "Actions on Objectives": "$1B+ stolen through fraudulent SWIFT transfers"
                },
                "impact": "Multiple banks compromised, $1 billion stolen globally",
                "lessons": "Financial sector security, insider threat programs, transaction monitoring"
            },
            "Colonial Pipeline Ransomware": {
                "year": "2021",
                "attribution": "DarkSide Ransomware Group",
                "target": "Critical Infrastructure",
                "kill_chain_analysis": {
                    "Reconnaissance": "Dark web reconnaissance, VPN credential harvesting",
                    "Weaponization": "DarkSide ransomware customization for target environment",
                    "Delivery": "Compromised VPN credentials, possible phishing vector",
                    "Exploitation": "Legacy VPN without MFA, network vulnerability exploitation",
                    "Installation": "Ransomware deployment, backup system targeting",
                    "Command & Control": "Ransomware-as-a-Service infrastructure management",
                    "Actions on Objectives": "100GB data theft, 5,500-mile pipeline shutdown"
                },
                "impact": "US fuel supply disruption, $4.4M ransom payment",
                "lessons": "Critical infrastructure protection, MFA implementation, backup security"
            }
        }
        
        selected_case = st.selectbox(
            "📖 Select Case Study:",
            list(case_studies.keys()),
            key="case_study_selector"
        )
        
        case = case_studies[selected_case]
        
        # Case study overview
        st.markdown(f"""
        <div style="background: {self.color_scheme['background']}; padding: 1.5rem; border-radius: 8px; margin: 1rem 0; border-left: 5px solid {self.color_scheme['primary']};">
            <h4 style="color: {self.color_scheme['primary']}; margin-top: 0;">📊 Case Overview</h4>
            <p><strong>Year:</strong> {case['year']}</p>
            <p><strong>Attribution:</strong> {case['attribution']}</p>
            <p><strong>Target:</strong> {case['target']}</p>
            <p><strong>Impact:</strong> {case['impact']}</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Kill chain mapping
        st.markdown("#### 🔗 Kill Chain Mapping")
        
        kill_chain_df = pd.DataFrame([
            {"Stage": stage, "Attacker Activity": activity}
            for stage, activity in case['kill_chain_analysis'].items()
        ])
        
        st.dataframe(kill_chain_df, use_container_width=True)
        
        # Lessons learned
        st.markdown("#### 📖 Key Lessons Learned")
        st.info(f"💡 **Strategic Insights:** {case['lessons']}")
    
    def _render_defense_strategies(self):
        """Render comprehensive defense strategies"""
        st.subheader("🛡️ Comprehensive Defense Strategies")
        
        defense_strategies = {
            "Early Stage Defense (Recon-Delivery)": {
                "description": "Focus on preventing initial compromise",
                "effectiveness": "90%+",
                "strategies": [
                    "External attack surface monitoring",
                    "Threat intelligence integration", 
                    "Employee security awareness training",
                    "Email security gateways with sandboxing",
                    "Web filtering and DNS protection",
                    "Endpoint protection with behavioral analysis"
                ],
                "tools": ["Shodan monitoring", "Have I Been Pwned", "PhishMe", "Proofpoint", "Zscaler"],
                "cost": "Low-Medium"
            },
            "Mid-Stage Defense (Exploit-Installation)": {
                "description": "Detect and contain active compromises",
                "effectiveness": "70-80%",
                "strategies": [
                    "Endpoint Detection and Response (EDR)",
                    "Network traffic analysis and monitoring",
                    "Vulnerability management and patching",
                    "Application whitelisting and control",
                    "Privilege access management (PAM)",
                    "File integrity monitoring (FIM)"
                ],
                "tools": ["CrowdStrike", "SentinelOne", "Splunk", "Carbon Black", "CyberArk"],
                "cost": "Medium-High"
            },
            "Late Stage Defense (C2-Actions)": {
                "description": "Minimize damage and enable recovery",
                "effectiveness": "40-60%",
                "strategies": [
                    "Data Loss Prevention (DLP) systems",
                    "Network segmentation and micro-segmentation",
                    "Backup and disaster recovery planning",
                    "Incident response and forensics capabilities",
                    "Threat hunting and advanced analytics",
                    "Business continuity planning"
                ],
                "tools": ["Varonis", "Illumio", "Veeam", "SANS DFIR", "Elastic Security"],
                "cost": "High"
            }
        }
        
        # Defense strategy visualization
        fig = go.Figure()
        
        stages = list(defense_strategies.keys())
        effectiveness = [90, 75, 50]  # Effectiveness percentages
        colors = [self.color_scheme['success'], self.color_scheme['warning'], self.color_scheme['danger']]
        
        fig.add_trace(go.Bar(
            x=stages,
            y=effectiveness,
            marker_color=colors,
            text=[f"{eff}%" for eff in effectiveness],
            textposition='auto',
        ))
        
        fig.update_layout(
            title="Defense Effectiveness by Kill Chain Stage",
            xaxis_title="Defense Strategy",
            yaxis_title="Effectiveness (%)",
            yaxis=dict(range=[0, 100]),
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Detailed defense strategies
        for strategy_name, strategy_info in defense_strategies.items():
            with st.expander(f"🔍 {strategy_name} - {strategy_info['effectiveness']} Effective"):
                create_info_card(
                    strategy_name,
                    strategy_info['description'],
                    card_type="info",
                    color_scheme=self.color_scheme
                )
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**🛠️ Key Strategies:**")
                    for strategy in strategy_info['strategies']:
                        st.markdown(f"• {strategy}")
                
                with col2:
                    st.markdown("**🔧 Recommended Tools:**")
                    for tool in strategy_info['tools']:
                        st.markdown(f"• {tool}")
                
                st.markdown(f"**💰 Cost Level:** {strategy_info['cost']}")
    
    def _render_modern_adaptations(self):
        """Render modern kill chain adaptations"""
        st.subheader("🚀 Modern Kill Chain Adaptations")
        
        modern_frameworks = {
            "MITRE ATT&CK Framework": {
                "year": "2013-Present",
                "focus": "Tactics, Techniques, and Procedures (TTPs)",
                "advantages": [
                    "Granular technique mapping",
                    "Regular updates with new techniques",
                    "Industry-wide adoption",
                    "Integration with security tools"
                ],
                "use_cases": ["Threat hunting", "Red teaming", "Security assessment"],
                "url": "https://attack.mitre.org/"
            },
            "Diamond Model": {
                "year": "2013",
                "focus": "Adversary, Infrastructure, Capability, Victim relationships",
                "advantages": [
                    "Multi-dimensional threat analysis",
                    "Attribution and correlation",
                    "Threat intelligence integration",
                    "Campaign tracking"
                ],
                "use_cases": ["Threat intelligence", "Attribution analysis", "Campaign tracking"],
                "url": "https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf"
            },
            "Unified Kill Chain": {
                "year": "2017",
                "focus": "Extended attack lifecycle including lateral movement",
                "advantages": [
                    "Covers full attack spectrum",
                    "Includes insider threats",
                    "Modern attack techniques",
                    "Cloud and IoT considerations"
                ],
                "use_cases": ["Comprehensive threat modeling", "Modern attack analysis"],
                "url": "https://unifiedkillchain.com/"
            }
        }
        
        st.markdown("#### 🔄 Evolution of Kill Chain Frameworks")
        
        for framework, details in modern_frameworks.items():
            with st.expander(f"📊 {framework} ({details['year']})"):
                st.markdown(f"**🎯 Focus:** {details['focus']}")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**✅ Key Advantages:**")
                    for advantage in details['advantages']:
                        st.markdown(f"• {advantage}")
                
                with col2:
                    st.markdown("**🎯 Use Cases:**")
                    for use_case in details['use_cases']:
                        st.markdown(f"• {use_case}")
                
                if details['url']:
                    st.markdown(f"**🔗 Resource:** [Official Documentation]({details['url']})")
    
    def _render_cheat_sheets(self):
        """Render comprehensive cheat sheets"""
        st.subheader("📋 Cyber Kill Chain Cheat Sheets")
        
        cheat_sheets = {
            "Kill Chain Stages": {
                "commands": [
                    {"Stage": "Reconnaissance", "Key Activities": "OSINT, Social Media, DNS Enum", "Tools": "theHarvester, Maltego, Shodan", "Detection": "External Monitoring"},
                    {"Stage": "Weaponization", "Key Activities": "Malware Creation, Exploit Prep", "Tools": "Metasploit, Cobalt Strike", "Detection": "Threat Intelligence"},
                    {"Stage": "Delivery", "Key Activities": "Phishing, Watering Holes", "Tools": "Email Campaigns, Web Exploits", "Detection": "Email/Web Security"},
                    {"Stage": "Exploitation", "Key Activities": "Code Execution, Vuln Exploit", "Tools": "Exploits, Living off Land", "Detection": "EDR, Behavioral Analysis"},
                    {"Stage": "Installation", "Key Activities": "Persistence, Backdoors", "Tools": "Registry, Scheduled Tasks", "Detection": "Host Monitoring"},
                    {"Stage": "C2", "Key Activities": "Communication Setup", "Tools": "HTTP/DNS Tunnels", "Detection": "Network Monitoring"},
                    {"Stage": "Actions", "Key Activities": "Data Theft, Destruction", "Tools": "Exfil Tools, Ransomware", "Detection": "DLP, Anomaly Detection"}
                ]
            },
            "Defense Priorities": {
                "commands": [
                    {"Priority": "1", "Stage": "Reconnaissance", "Defense": "Attack Surface Monitoring", "Cost": "Low", "Effectiveness": "90%"},
                    {"Priority": "2", "Stage": "Delivery", "Defense": "Email Security + Training", "Cost": "Medium", "Effectiveness": "85%"},
                    {"Priority": "3", "Stage": "Exploitation", "Defense": "Patch Management + EDR", "Cost": "Medium", "Effectiveness": "80%"},
                    {"Priority": "4", "Stage": "Installation", "Defense": "Host Monitoring + FIM", "Cost": "Medium", "Effectiveness": "75%"},
                    {"Priority": "5", "Stage": "C2", "Defense": "Network Monitoring", "Cost": "High", "Effectiveness": "70%"},
                    {"Priority": "6", "Stage": "Actions", "Defense": "DLP + Backup", "Cost": "High", "Effectiveness": "50%"}
                ]
            },
            "Modern Techniques": {
                "commands": [
                    {"Category": "AI-Enhanced", "Technique": "Automated OSINT", "Description": "AI-powered reconnaissance", "Countermeasure": "AI-powered Defense"},
                    {"Category": "Cloud-Native", "Technique": "Container Escape", "Description": "Cloud workload compromise", "Countermeasure": "Container Security"},
                    {"Category": "Supply Chain", "Technique": "Software Compromise", "Description": "Third-party software backdoors", "Countermeasure": "Supply Chain Security"},
                    {"Category": "Living off Land", "Technique": "PowerShell Abuse", "Description": "Legitimate tool misuse", "Countermeasure": "Behavioral Monitoring"},
                    {"Category": "Fileless", "Technique": "Memory-only Attacks", "Description": "No disk artifacts", "Countermeasure": "Memory Protection"}
                ]
            }
        }
        
        create_cheat_sheet_tabs(cheat_sheets, self.color_scheme)


def explain_cyber_kill_chain():
    """Main function to render Cyber Kill Chain component"""
    component = CyberKillChainComponent()
    
    # Summary points for the component
    summary_points = [
        "Cyber Kill Chain provides a structured framework for understanding attack progression",
        "Early-stage defenses (reconnaissance-delivery) are most cost-effective with 90%+ prevention rates",
        "Modern adaptations like MITRE ATT&CK provide more granular technique mapping",
        "Real-world case studies demonstrate the framework's practical application in threat analysis",
        "Comprehensive defense requires layered strategies across all kill chain stages"
    ]
    
    # Additional resources with latest 2024 updates
    resources = [
        {
            "title": "Lockheed Martin Cyber Kill Chain® (Official)",
            "description": "Original framework documentation and latest updates",
            "url": "https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html"
        },
        {
            "title": "MITRE ATT&CK Framework",
            "description": "Modern adaptation with detailed technique mapping",
            "url": "https://attack.mitre.org/"
        },
        {
            "title": "SANS Cyber Kill Chain Course",
            "description": "Comprehensive training on kill chain analysis",
            "url": "https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-digital-forensics/"
        },
        {
            "title": "Unified Kill Chain",
            "description": "Extended framework covering modern attack techniques",
            "url": "https://unifiedkillchain.com/"
        },
        {
            "title": "Cyber Kill Chain Case Studies (2024)",
            "description": "Latest real-world attack analysis and lessons learned"
        }
    ]
    
    # Render the complete component
    component.render_full_component(summary_points, resources)
