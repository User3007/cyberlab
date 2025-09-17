"""
DevSecOps Lab
Security integration in CI/CD pipelines and development lifecycle
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import time
import hashlib
import random
from datetime import datetime, timedelta
import base64
from typing import Dict, List, Tuple, Optional, Any

def create_lab_header(title: str, icon: str, gradient: str = "linear-gradient(90deg, #667eea 0%, #764ba2 100%)"):
    """Create compact lab header"""
    return f"""
    <div style="background: {gradient}; 
                padding: 0.8rem; border-radius: 6px; margin-bottom: 1rem;">
        <h3 style="color: white; margin: 0; font-size: 1.2rem;">{icon} {title}</h3>
    </div>
    """

def run_lab():
    """DevSecOps Lab - Integrating Security into DevOps"""
    
    # Compact Header
    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 1rem; border-radius: 8px; margin-bottom: 1rem; text-align: center;">
        <h2 style="color: white; margin: 0; font-size: 1.5rem;">
            🔧 DevSecOps Lab
        </h2>
        <p style="color: white; margin: 0; font-size: 0.9rem; opacity: 0.9;">
            CI/CD Security, Supply Chain Protection & Automation
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # DevSecOps topics tabs
    tabs = st.tabs([
        "🔄 CI/CD Security",
        "🔍 SAST",
        "🎯 DAST",
        "📦 SCA",
        "🐳 Container Scanning",
        "🔐 Secret Management",
        "📋 IaC Security",
        "🔗 Supply Chain",
        "🚀 GitOps Security",
        "📊 Security Metrics",
        "🤖 Automation",
        "🛡️ Policy as Code"
    ])
    
    with tabs[0]:
        cicd_security_lab()
    
    with tabs[1]:
        sast_lab()
    
    with tabs[2]:
        dast_lab()
    
    with tabs[3]:
        sca_lab()
    
    with tabs[4]:
        container_scanning_lab()
    
    with tabs[5]:
        secret_management_lab()
    
    with tabs[6]:
        iac_security_lab()
    
    with tabs[7]:
        supply_chain_lab()
    
    with tabs[8]:
        gitops_security_lab()
    
    with tabs[9]:
        security_metrics_lab()
    
    with tabs[10]:
        automation_lab()
    
    with tabs[11]:
        policy_as_code_lab()

def cicd_security_lab():
    """CI/CD Pipeline Security"""
    
    st.markdown(create_lab_header("CI/CD Security Lab", "🔄", "linear-gradient(90deg, #FF6B6B 0%, #4ECDC4 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **CI/CD Security Theory**", expanded=True):
        st.markdown("""
        ### 🔄 **Understanding CI/CD Pipeline Security**
        
        CI/CD pipelines are the backbone of modern software delivery but are increasingly targeted by attackers 
        due to their privileged access to code, secrets, and production environments.
        
        **Why Target CI/CD Pipelines?**
        - 🔑 **Privileged Access** - Deploy to production
        - 🔐 **Secret Storage** - API keys, passwords
        - 📦 **Supply Chain** - Inject malicious code
        - 🎯 **Lateral Movement** - Access to multiple systems
        
        **Common Attack Vectors:**
        
        1. **Poisoned Pipeline Execution (PPE)**
           - Inject malicious code via PR
           - Execute during build process
           - Example: Codecov breach (2021)
        
        2. **Dependency Confusion**
           - Upload malicious public packages
           - Override private packages
           - npm, PyPI, Maven attacks
        
        3. **Secret Extraction**
           - Exfiltrate environment variables
           - Access to secret stores
           - Leaked in logs/artifacts
        
        4. **Pipeline Hijacking**
           - Modify pipeline configuration
           - Bypass security checks
           - Direct deployment to production
        
        **Real-World Incidents:**
        - **SolarWinds (2020)** - Build system compromised
        - **Codecov (2021)** - Bash uploader modified
        - **GitHub Actions (2023)** - Workflow injection attacks
        - **CircleCI (2023)** - Secrets exposed
        
        **Security Controls:**
        
        **Pre-Commit:**
        - Secret scanning (pre-commit hooks)
        - Code signing
        - Developer security training
        
        **Build Phase:**
        - SAST (Static Analysis)
        - Dependency scanning
        - Container scanning
        - License compliance
        
        **Test Phase:**
        - DAST (Dynamic Analysis)
        - Security unit tests
        - Penetration testing
        
        **Deploy Phase:**
        - Environment segregation
        - Approval workflows
        - Rollback capabilities
        
        **Best Practices:**
        - Least privilege for pipeline
        - Immutable infrastructure
        - Signed commits & artifacts
        - Audit logging
        - Regular security reviews
        """)
    
    # Pipeline Security
    st.markdown("### 🔒 **Secure CI/CD Pipeline**")
    
    pipeline_tool = st.selectbox("CI/CD Tool:", ["Jenkins", "GitLab CI", "GitHub Actions", "Azure DevOps"])
    
    if pipeline_tool == "GitHub Actions":
        st.markdown("#### **GitHub Actions Security**")
        
        st.code("""
        name: Secure CI/CD Pipeline
        
        on:
          push:
            branches: [ main, develop ]
          pull_request:
            branches: [ main ]
        
        env:
          # Security: Don't expose secrets in logs
          ACTIONS_STEP_DEBUG: false
        
        permissions:
          # Principle of least privilege
          contents: read
          security-events: write
          actions: read
        
        jobs:
          security-scan:
            runs-on: ubuntu-latest
            
            steps:
            - name: Checkout code
              uses: actions/checkout@v3
              with:
                # Fetch full history for better scanning
                fetch-depth: 0
            
            - name: Run TruffleHog (Secret Scanning)
              uses: trufflesecurity/trufflehog@main
              with:
                path: ./
                base: ${{ github.event.repository.default_branch }}
                head: HEAD
            
            - name: SAST with Semgrep
              uses: returntocorp/semgrep-action@v1
              with:
                config: >-
                  p/security-audit
                  p/owasp-top-ten
                  p/r2c-security-audit
            
            - name: Run Snyk Security Scan
              uses: snyk/actions/node@master
              env:
                SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
              with:
                args: --severity-threshold=high
            
            - name: Container Scan with Trivy
              uses: aquasecurity/trivy-action@master
              with:
                image-ref: '${{ env.IMAGE_NAME }}:${{ github.sha }}'
                format: 'sarif'
                output: 'trivy-results.sarif'
            
            - name: Upload results to GitHub Security
              uses: github/codeql-action/upload-sarif@v2
              with:
                sarif_file: 'trivy-results.sarif'
            
            - name: OWASP Dependency Check
              uses: dependency-check/Dependency-Check_Action@main
              with:
                project: 'MyApp'
                path: '.'
                format: 'ALL'
            
            - name: License Compliance Check
              run: |
                pip install licensecheck
                licensecheck --zero --file requirements.txt
            
          build:
            needs: security-scan
            runs-on: ubuntu-latest
            
            steps:
            - name: Set up Docker Buildx
              uses: docker/setup-buildx-action@v2
            
            - name: Build with security hardening
              uses: docker/build-push-action@v4
              with:
                context: .
                push: false
                tags: ${{ env.IMAGE_NAME }}:${{ github.sha }}
                # Security: Use BuildKit for better caching and security
                cache-from: type=gha
                cache-to: type=gha,mode=max
                # Security: Don't leak build secrets
                secret-files: |
                  "npmrc=${{ secrets.NPMRC }}"
            
            - name: Sign container image
              uses: sigstore/cosign-installer@v3
              run: |
                cosign sign --key env://COSIGN_KEY \\
                  ${{ env.IMAGE_NAME }}:${{ github.sha }}
            
          deploy:
            needs: build
            runs-on: ubuntu-latest
            environment: production
            
            steps:
            - name: Verify image signature
              run: |
                cosign verify --key env://COSIGN_PUBLIC_KEY \\
                  ${{ env.IMAGE_NAME }}:${{ github.sha }}
            
            - name: Deploy with security policies
              run: |
                # Apply security policies before deployment
                kubectl apply -f k8s/network-policies.yaml
                kubectl apply -f k8s/pod-security-policies.yaml
                
                # Deploy application
                kubectl set image deployment/myapp \\
                  myapp=${{ env.IMAGE_NAME }}:${{ github.sha }}
        """, language="yaml")
    
    elif pipeline_tool == "Jenkins":
        st.markdown("#### **Jenkins Pipeline Security**")
        
        st.code("""
        pipeline {
            agent any
            
            environment {
                // Use credentials binding for secrets
                SONAR_TOKEN = credentials('sonar-token')
                DOCKER_CREDS = credentials('docker-hub')
            }
            
            options {
                // Security: Limit build history
                buildDiscarder(logRotator(numToKeepStr: '10'))
                // Security: Timeout builds
                timeout(time: 1, unit: 'HOURS')
                // Security: Don't allow concurrent builds
                disableConcurrentBuilds()
            }
            
            stages {
                stage('Security Checks') {
                    parallel {
                        stage('Secret Scanning') {
                            steps {
                                sh '''
                                    # Scan for secrets
                                    docker run --rm -v "$PWD:/pwd" \\
                                        trufflesecurity/trufflehog:latest \\
                                        filesystem /pwd --json
                                '''
                            }
                        }
                        
                        stage('SAST Scan') {
                            steps {
                                withSonarQubeEnv('SonarQube') {
                                    sh '''
                                        sonar-scanner \\
                                            -Dsonar.projectKey=myapp \\
                                            -Dsonar.sources=. \\
                                            -Dsonar.host.url=$SONAR_HOST_URL \\
                                            -Dsonar.login=$SONAR_TOKEN
                                    '''
                                }
                            }
                        }
                        
                        stage('Dependency Check') {
                            steps {
                                dependencyCheck additionalArguments: '''
                                    --scan .
                                    --format ALL
                                    --project "MyApp"
                                ''', odcInstallation: 'OWASP-DC'
                                
                                publishHTML(target: [
                                    reportDir: 'dependency-check-report',
                                    reportFiles: 'dependency-check-report.html',
                                    reportName: 'OWASP Dependency Check'
                                ])
                            }
                        }
                    }
                }
                
                stage('Build') {
                    steps {
                        script {
                            // Build with security flags
                            docker.build("myapp:${env.BUILD_ID}", 
                                "--build-arg BUILDKIT_INLINE_CACHE=1 " +
                                "--label security.scan=passed .")
                        }
                    }
                }
                
                stage('Container Security') {
                    steps {
                        // Scan container with Anchore
                        writeFile file: 'anchore_images', 
                                  text: "myapp:${env.BUILD_ID}"
                        
                        anchore name: 'anchore_images',
                                engineCredentialsId: 'anchore-creds',
                                annotations: [[key: 'build_id', value: env.BUILD_ID]]
                    }
                }
                
                stage('Deploy') {
                    when {
                        branch 'main'
                    }
                    steps {
                        // Deploy only if all security checks pass
                        script {
                            if (currentBuild.result == null || 
                                currentBuild.result == 'SUCCESS') {
                                sh 'kubectl apply -f k8s/'
                            } else {
                                error 'Security checks failed'
                            }
                        }
                    }
                }
            }
            
            post {
                always {
                    // Clean up sensitive data
                    sh 'rm -rf .env secrets/ *.key'
                }
                failure {
                    // Notify security team
                    emailext to: 'security@company.com',
                             subject: 'Security scan failed',
                             body: 'Check Jenkins for details'
                }
            }
        }
        """, language="groovy")
    
    # Pipeline Security Best Practices
    st.markdown("### ✅ **CI/CD Security Best Practices**")
    
    practices = [
        "Use least privilege for pipeline permissions",
        "Scan for secrets in code and commits",
        "Implement branch protection rules",
        "Sign commits and tags",
        "Use ephemeral build environments",
        "Implement security gates",
        "Audit pipeline configurations",
        "Rotate credentials regularly",
        "Use private runners/agents",
        "Implement artifact signing"
    ]
    
    for practice in practices:
        st.success(f"✓ {practice}")

def sast_lab():
    """Static Application Security Testing"""
    
    st.markdown(create_lab_header("SAST Lab", "🔍", "linear-gradient(90deg, #667eea 0%, #764ba2 100%)"), unsafe_allow_html=True)
    
    # SAST Tools
    st.markdown("### 🛠️ **SAST Tools Comparison**")
    
    tools_data = {
        "Tool": ["SonarQube", "Semgrep", "CodeQL", "Checkmarx", "Veracode"],
        "Languages": ["25+", "20+", "10+", "30+", "25+"],
        "Speed": ["Medium", "Fast", "Slow", "Slow", "Medium"],
        "Accuracy": ["High", "High", "Very High", "High", "High"],
        "CI/CD Integration": ["Excellent", "Excellent", "Good", "Good", "Good"],
        "Cost": ["Free/Paid", "Free/Paid", "Free", "Paid", "Paid"]
    }
    
    df = pd.DataFrame(tools_data)
    st.dataframe(df, use_container_width=True)
    
    # SAST Implementation
    st.markdown("### 💻 **SAST Implementation**")
    
    language = st.selectbox("Programming Language:", ["Python", "JavaScript", "Java", "Go", "C#"])
    
    if language == "Python":
        st.code("""
        # Python SAST with Bandit and Semgrep
        
        import subprocess
        import json
        from typing import List, Dict
        
        class PythonSASTScanner:
            def __init__(self, project_path: str):
                self.project_path = project_path
                self.vulnerabilities = []
                
            def run_bandit(self) -> List[Dict]:
                '''Run Bandit security linter'''
                
                try:
                    result = subprocess.run(
                        ['bandit', '-r', self.project_path, '-f', 'json'],
                        capture_output=True,
                        text=True
                    )
                    
                    findings = json.loads(result.stdout)
                    
                    vulnerabilities = []
                    for issue in findings.get('results', []):
                        vulnerabilities.append({
                            'tool': 'Bandit',
                            'severity': issue['issue_severity'],
                            'confidence': issue['issue_confidence'],
                            'cwe': issue.get('issue_cwe', {}).get('id'),
                            'message': issue['issue_text'],
                            'filename': issue['filename'],
                            'line': issue['line_number'],
                            'code': issue['code']
                        })
                    
                    return vulnerabilities
                    
                except Exception as e:
                    return [{'error': str(e)}]
            
            def run_semgrep(self) -> List[Dict]:
                '''Run Semgrep with security rules'''
                
                try:
                    result = subprocess.run([
                        'semgrep',
                        '--config=auto',
                        '--json',
                        self.project_path
                    ], capture_output=True, text=True)
                    
                    findings = json.loads(result.stdout)
                    
                    vulnerabilities = []
                    for issue in findings.get('results', []):
                        vulnerabilities.append({
                            'tool': 'Semgrep',
                            'rule_id': issue['check_id'],
                            'severity': issue['extra']['severity'],
                            'message': issue['extra']['message'],
                            'filename': issue['path'],
                            'line_start': issue['start']['line'],
                            'line_end': issue['end']['line'],
                            'fix': issue.get('extra', {}).get('fix')
                        })
                    
                    return vulnerabilities
                    
                except Exception as e:
                    return [{'error': str(e)}]
            
            def custom_checks(self) -> List[Dict]:
                '''Custom security checks for Python'''
                
                vulnerabilities = []
                dangerous_imports = [
                    'pickle', 'subprocess', 'os', 'eval', 'exec',
                    '__import__', 'compile'
                ]
                
                import ast
                import os
                
                for root, dirs, files in os.walk(self.project_path):
                    for file in files:
                        if file.endswith('.py'):
                            filepath = os.path.join(root, file)
                            
                            with open(filepath, 'r') as f:
                                try:
                                    tree = ast.parse(f.read())
                                    
                                    # Check for dangerous imports
                                    for node in ast.walk(tree):
                                        if isinstance(node, ast.Import):
                                            for alias in node.names:
                                                if alias.name in dangerous_imports:
                                                    vulnerabilities.append({
                                                        'tool': 'Custom',
                                                        'severity': 'MEDIUM',
                                                        'message': f'Dangerous import: {alias.name}',
                                                        'filename': filepath,
                                                        'line': node.lineno
                                                    })
                                        
                                        # Check for hardcoded secrets
                                        if isinstance(node, ast.Assign):
                                            for target in node.targets:
                                                if isinstance(target, ast.Name):
                                                    var_name = target.id.upper()
                                                    if any(secret in var_name for secret in 
                                                          ['PASSWORD', 'SECRET', 'KEY', 'TOKEN']):
                                                        if isinstance(node.value, ast.Str):
                                                            vulnerabilities.append({
                                                                'tool': 'Custom',
                                                                'severity': 'HIGH',
                                                                'message': f'Hardcoded secret: {target.id}',
                                                                'filename': filepath,
                                                                'line': node.lineno
                                                            })
                                
                                except SyntaxError:
                                    pass
                
                return vulnerabilities
            
            def generate_report(self) -> Dict:
                '''Generate comprehensive SAST report'''
                
                # Run all scanners
                bandit_results = self.run_bandit()
                semgrep_results = self.run_semgrep()
                custom_results = self.custom_checks()
                
                # Combine results
                all_vulnerabilities = bandit_results + semgrep_results + custom_results
                
                # Statistics
                severity_counts = {
                    'CRITICAL': 0,
                    'HIGH': 0,
                    'MEDIUM': 0,
                    'LOW': 0
                }
                
                for vuln in all_vulnerabilities:
                    severity = vuln.get('severity', 'LOW').upper()
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                report = {
                    'scan_date': datetime.now().isoformat(),
                    'project': self.project_path,
                    'total_issues': len(all_vulnerabilities),
                    'severity_breakdown': severity_counts,
                    'vulnerabilities': all_vulnerabilities,
                    'risk_score': self.calculate_risk_score(severity_counts)
                }
                
                return report
            
            def calculate_risk_score(self, severity_counts: Dict) -> int:
                '''Calculate overall risk score'''
                
                weights = {
                    'CRITICAL': 10,
                    'HIGH': 5,
                    'MEDIUM': 2,
                    'LOW': 1
                }
                
                score = 0
                for severity, count in severity_counts.items():
                    score += weights.get(severity, 0) * count
                
                # Normalize to 0-100
                max_score = sum(weights.values()) * 10  # Assume max 10 issues per severity
                normalized = min(100, (score / max_score) * 100)
                
                return int(normalized)
        """, language="python")
    
    # SAST Results Dashboard
    st.markdown("### 📊 **SAST Results Dashboard**")
    
    # Simulate scan results
    vulnerabilities = {
        "Type": ["SQL Injection", "XSS", "Hardcoded Secrets", "Insecure Deserialization", "Path Traversal"],
        "Count": [3, 7, 12, 2, 5],
        "Severity": ["Critical", "High", "Critical", "High", "Medium"]
    }
    
    df_vulns = pd.DataFrame(vulnerabilities)
    
    fig = px.bar(df_vulns, x="Type", y="Count", color="Severity",
                 title="SAST Findings by Type",
                 color_discrete_map={"Critical": "red", "High": "orange", "Medium": "yellow"})
    st.plotly_chart(fig, use_container_width=True)

def dast_lab():
    """Dynamic Application Security Testing"""
    
    st.markdown(create_lab_header("DAST Lab", "🎯", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    # DAST Configuration
    st.markdown("### 🔧 **DAST Configuration**")
    
    st.code("""
    # OWASP ZAP DAST Automation
    
    import requests
    import time
    from zapv2 import ZAPv2
    
    class DASTScanner:
        def __init__(self, target_url, zap_proxy='http://localhost:8080'):
            self.target = target_url
            self.zap = ZAPv2(proxies={'http': zap_proxy, 'https': zap_proxy})
            
        def run_spider(self):
            '''Spider the target application'''
            
            print(f"Spidering {self.target}")
            scan_id = self.zap.spider.scan(self.target)
            
            # Wait for spider to complete
            while int(self.zap.spider.status(scan_id)) < 100:
                print(f"Spider progress: {self.zap.spider.status(scan_id)}%")
                time.sleep(2)
            
            print("Spider completed")
            return self.zap.spider.results(scan_id)
        
        def run_active_scan(self):
            '''Run active security scan'''
            
            print(f"Active scanning {self.target}")
            scan_id = self.zap.ascan.scan(self.target)
            
            # Wait for scan to complete
            while int(self.zap.ascan.status(scan_id)) < 100:
                print(f"Scan progress: {self.zap.ascan.status(scan_id)}%")
                time.sleep(5)
            
            print("Active scan completed")
            return scan_id
        
        def run_ajax_spider(self):
            '''Spider AJAX/SPA applications'''
            
            print("Starting AJAX spider")
            self.zap.ajaxSpider.scan(self.target)
            
            # Wait for AJAX spider
            while self.zap.ajaxSpider.status == 'running':
                print(f"AJAX Spider running...")
                time.sleep(5)
            
            return self.zap.ajaxSpider.results()
        
        def get_alerts(self):
            '''Get security alerts'''
            
            alerts = self.zap.core.alerts(baseurl=self.target)
            
            # Categorize by risk
            categorized = {
                'High': [],
                'Medium': [],
                'Low': [],
                'Informational': []
            }
            
            for alert in alerts:
                risk = alert.get('risk')
                categorized[risk].append({
                    'name': alert.get('name'),
                    'description': alert.get('description'),
                    'url': alert.get('url'),
                    'solution': alert.get('solution'),
                    'evidence': alert.get('evidence'),
                    'cwe': alert.get('cweid'),
                    'wasc': alert.get('wascid')
                })
            
            return categorized
        
        def generate_report(self):
            '''Generate DAST report'''
            
            # Get various report formats
            html_report = self.zap.core.htmlreport()
            json_report = self.zap.core.jsonreport()
            
            # Save reports
            with open('dast_report.html', 'w') as f:
                f.write(html_report)
            
            with open('dast_report.json', 'w') as f:
                f.write(json_report)
            
            return {
                'html': 'dast_report.html',
                'json': 'dast_report.json'
            }
    
    # Burp Suite Integration
    class BurpSuiteScanner:
        def __init__(self, api_url, api_key):
            self.api_url = api_url
            self.headers = {'Authorization': f'Bearer {api_key}'}
            
        def create_scan(self, target_url):
            '''Create new scan'''
            
            scan_config = {
                'scan_configurations': [{
                    'name': 'Default',
                    'type': 'NamedConfiguration'
                }],
                'scope': {
                    'include': [{
                        'rule': target_url,
                        'type': 'SimpleScopeDef'
                    }]
                }
            }
            
            response = requests.post(
                f'{self.api_url}/scan',
                json=scan_config,
                headers=self.headers
            )
            
            return response.json()['scan_id']
        
        def get_scan_status(self, scan_id):
            '''Get scan status'''
            
            response = requests.get(
                f'{self.api_url}/scan/{scan_id}',
                headers=self.headers
            )
            
            return response.json()
        
        def get_issues(self, scan_id):
            '''Get discovered issues'''
            
            response = requests.get(
                f'{self.api_url}/scan/{scan_id}/issues',
                headers=self.headers
            )
            
            return response.json()
    """, language="python")
    
    # DAST Test Cases
    st.markdown("### 🎯 **DAST Test Cases**")
    
    test_categories = {
        "Category": ["Authentication", "Authorization", "Input Validation", "Session Management", "Business Logic"],
        "Tests": [15, 12, 25, 10, 8],
        "Passed": [12, 10, 20, 8, 7],
        "Failed": [3, 2, 5, 2, 1]
    }
    
    df = pd.DataFrame(test_categories)
    
    fig = go.Figure()
    fig.add_trace(go.Bar(name='Passed', x=df['Category'], y=df['Passed'], marker_color='green'))
    fig.add_trace(go.Bar(name='Failed', x=df['Category'], y=df['Failed'], marker_color='red'))
    
    fig.update_layout(barmode='stack', title='DAST Test Results')
    st.plotly_chart(fig, use_container_width=True)

def sca_lab():
    """Software Composition Analysis"""
    
    st.markdown(create_lab_header("SCA Lab", "📦", "linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)"), unsafe_allow_html=True)
    
    # Dependency Scanning
    st.markdown("### 🔍 **Dependency Vulnerability Scanning**")
    
    st.code("""
    # Multi-language SCA Scanner
    
    import json
    import subprocess
    from typing import List, Dict
    import requests
    
    class SCAScanner:
        def __init__(self):
            self.vulnerabilities = []
            self.licenses = []
            
        def scan_python_dependencies(self, requirements_file='requirements.txt'):
            '''Scan Python dependencies with Safety'''
            
            try:
                # Run safety check
                result = subprocess.run(
                    ['safety', 'check', '--json', '--file', requirements_file],
                    capture_output=True,
                    text=True
                )
                
                vulnerabilities = json.loads(result.stdout)
                
                findings = []
                for vuln in vulnerabilities:
                    findings.append({
                        'language': 'Python',
                        'package': vuln['package'],
                        'installed_version': vuln['installed_version'],
                        'affected_versions': vuln['affected_versions'],
                        'vulnerability': vuln['vulnerability'],
                        'severity': self.get_severity_from_cvss(vuln.get('cvssv3', {}).get('base_score', 0)),
                        'cve': vuln.get('cve'),
                        'advisory': vuln.get('advisory')
                    })
                
                return findings
                
            except Exception as e:
                return [{'error': str(e)}]
        
        def scan_npm_dependencies(self, package_file='package.json'):
            '''Scan Node.js dependencies with npm audit'''
            
            try:
                result = subprocess.run(
                    ['npm', 'audit', '--json'],
                    capture_output=True,
                    text=True,
                    cwd=os.path.dirname(package_file)
                )
                
                audit_data = json.loads(result.stdout)
                
                findings = []
                for advisory_id, advisory in audit_data.get('advisories', {}).items():
                    findings.append({
                        'language': 'JavaScript',
                        'package': advisory['module_name'],
                        'severity': advisory['severity'],
                        'title': advisory['title'],
                        'vulnerable_versions': advisory['vulnerable_versions'],
                        'patched_versions': advisory['patched_versions'],
                        'cve': advisory.get('cves', []),
                        'recommendation': advisory['recommendation']
                    })
                
                return findings
                
            except Exception as e:
                return [{'error': str(e)}]
        
        def scan_java_dependencies(self, pom_file='pom.xml'):
            '''Scan Java dependencies with OWASP Dependency Check'''
            
            try:
                result = subprocess.run([
                    'dependency-check',
                    '--scan', pom_file,
                    '--format', 'JSON',
                    '--out', 'dependency-check-report.json'
                ], capture_output=True, text=True)
                
                with open('dependency-check-report.json', 'r') as f:
                    report = json.load(f)
                
                findings = []
                for dependency in report.get('dependencies', []):
                    for vulnerability in dependency.get('vulnerabilities', []):
                        findings.append({
                            'language': 'Java',
                            'package': dependency['fileName'],
                            'cve': vulnerability['name'],
                            'severity': vulnerability['severity'],
                            'description': vulnerability['description'],
                            'cvss_score': vulnerability.get('cvssv3', {}).get('baseScore')
                        })
                
                return findings
                
            except Exception as e:
                return [{'error': str(e)}]
        
        def check_licenses(self, project_path):
            '''Check for license compliance'''
            
            # Use license-checker for Node.js projects
            try:
                result = subprocess.run(
                    ['license-checker', '--json'],
                    capture_output=True,
                    text=True,
                    cwd=project_path
                )
                
                licenses = json.loads(result.stdout)
                
                # Categorize licenses
                license_categories = {
                    'permissive': ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'BSD-2-Clause'],
                    'copyleft': ['GPL-3.0', 'GPL-2.0', 'AGPL-3.0'],
                    'weak_copyleft': ['LGPL-3.0', 'LGPL-2.1', 'MPL-2.0'],
                    'proprietary': ['UNLICENSED', 'SEE LICENSE IN'],
                    'unknown': []
                }
                
                findings = {
                    'total_packages': len(licenses),
                    'license_breakdown': {},
                    'risky_licenses': []
                }
                
                for package, info in licenses.items():
                    license_type = info.get('licenses', 'Unknown')
                    
                    # Check for risky licenses
                    if license_type in license_categories['copyleft']:
                        findings['risky_licenses'].append({
                            'package': package,
                            'license': license_type,
                            'risk': 'Copyleft - may require source disclosure'
                        })
                    
                    # Count licenses
                    findings['license_breakdown'][license_type] = \\
                        findings['license_breakdown'].get(license_type, 0) + 1
                
                return findings
                
            except Exception as e:
                return {'error': str(e)}
        
        def generate_sbom(self, project_path, format='cyclonedx'):
            '''Generate Software Bill of Materials'''
            
            if format == 'cyclonedx':
                # Generate CycloneDX SBOM
                subprocess.run([
                    'cyclonedx-py',
                    '-i', f'{project_path}/requirements.txt',
                    '-o', 'sbom.json',
                    '--format', 'json'
                ])
                
                with open('sbom.json', 'r') as f:
                    sbom = json.load(f)
                
                return sbom
            
            elif format == 'spdx':
                # Generate SPDX SBOM
                subprocess.run([
                    'spdx-sbom-generator',
                    '-p', project_path,
                    '-o', 'sbom.spdx'
                ])
                
                with open('sbom.spdx', 'r') as f:
                    sbom = f.read()
                
                return sbom
    """, language="python")
    
    # Vulnerability Metrics
    st.markdown("### 📊 **Dependency Vulnerability Metrics**")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Dependencies", "247")
        st.metric("Direct", "52")
    
    with col2:
        st.metric("Vulnerable", "14", "⚠️")
        st.metric("Critical", "3", "🔴")
    
    with col3:
        st.metric("Outdated", "38")
        st.metric("License Issues", "2")
    
    with col4:
        st.metric("SBOM Generated", "✅")
        st.metric("Last Scan", "2 min ago")

def container_scanning_lab():
    """Container Security Scanning"""
    
    st.markdown(create_lab_header("Container Scanning Lab", "🐳", "linear-gradient(90deg, #00C9FF 0%, #92FE9D 100%)"), unsafe_allow_html=True)
    
    # Container Scanning Tools
    st.markdown("### 🔍 **Container Security Scanning**")
    
    st.code("""
    # Container Security Scanner
    
    import docker
    import json
    import subprocess
    from typing import Dict, List
    
    class ContainerSecurityScanner:
        def __init__(self):
            self.docker_client = docker.from_env()
            
        def scan_with_trivy(self, image_name: str) -> Dict:
            '''Scan container with Trivy'''
            
            try:
                result = subprocess.run([
                    'trivy', 'image',
                    '--format', 'json',
                    '--severity', 'CRITICAL,HIGH,MEDIUM',
                    image_name
                ], capture_output=True, text=True)
                
                scan_results = json.loads(result.stdout)
                
                vulnerabilities = []
                for result in scan_results.get('Results', []):
                    for vuln in result.get('Vulnerabilities', []):
                        vulnerabilities.append({
                            'id': vuln['VulnerabilityID'],
                            'package': vuln['PkgName'],
                            'version': vuln['InstalledVersion'],
                            'fixed_version': vuln.get('FixedVersion', 'No fix'),
                            'severity': vuln['Severity'],
                            'title': vuln.get('Title', ''),
                            'description': vuln.get('Description', ''),
                            'references': vuln.get('References', [])
                        })
                
                return {
                    'image': image_name,
                    'scan_date': datetime.now().isoformat(),
                    'vulnerabilities': vulnerabilities,
                    'summary': self.summarize_vulnerabilities(vulnerabilities)
                }
                
            except Exception as e:
                return {'error': str(e)}
        
        def scan_with_clair(self, image_name: str) -> Dict:
            '''Scan with Clair vulnerability scanner'''
            
            # Clair API integration
            clair_url = 'http://localhost:6060'
            
            # Analyze layers
            image = self.docker_client.images.get(image_name)
            layers = image.history()
            
            vulnerabilities = []
            for layer in layers:
                # Send layer to Clair for analysis
                # This is simplified - actual implementation would extract layer
                layer_hash = layer.get('Id')
                
                response = requests.post(
                    f'{clair_url}/v1/layers',
                    json={
                        'Layer': {
                            'Name': layer_hash,
                            'Path': f'/tmp/{layer_hash}.tar',
                            'Format': 'Docker'
                        }
                    }
                )
                
                # Get vulnerabilities for layer
                vuln_response = requests.get(
                    f'{clair_url}/v1/layers/{layer_hash}?features&vulnerabilities'
                )
                
                if vuln_response.status_code == 200:
                    layer_vulns = vuln_response.json()
                    vulnerabilities.extend(layer_vulns.get('Vulnerabilities', []))
            
            return vulnerabilities
        
        def scan_dockerfile(self, dockerfile_path: str) -> List[Dict]:
            '''Scan Dockerfile for security issues'''
            
            issues = []
            
            with open(dockerfile_path, 'r') as f:
                lines = f.readlines()
            
            for i, line in enumerate(lines, 1):
                line = line.strip()
                
                # Check for running as root
                if line.startswith('USER') and 'root' in line:
                    issues.append({
                        'line': i,
                        'severity': 'HIGH',
                        'issue': 'Running as root user',
                        'recommendation': 'Use non-root user'
                    })
                
                # Check for sudo installation
                if 'apt-get install' in line and 'sudo' in line:
                    issues.append({
                        'line': i,
                        'severity': 'MEDIUM',
                        'issue': 'Installing sudo in container',
                        'recommendation': 'Avoid sudo in containers'
                    })
                
                # Check for latest tag
                if line.startswith('FROM') and ':latest' in line:
                    issues.append({
                        'line': i,
                        'severity': 'MEDIUM',
                        'issue': 'Using latest tag',
                        'recommendation': 'Use specific version tags'
                    })
                
                # Check for ADD instead of COPY
                if line.startswith('ADD') and not line.endswith('.tar'):
                    issues.append({
                        'line': i,
                        'severity': 'LOW',
                        'issue': 'Using ADD instead of COPY',
                        'recommendation': 'Use COPY unless extracting archives'
                    })
                
                # Check for secrets
                if any(secret in line.upper() for secret in ['PASSWORD', 'SECRET', 'KEY', 'TOKEN']):
                    if '=' in line or 'ENV' in line:
                        issues.append({
                            'line': i,
                            'severity': 'CRITICAL',
                            'issue': 'Potential hardcoded secret',
                            'recommendation': 'Use secrets management'
                        })
                
                # Check for unnecessary packages
                if 'apt-get install' in line:
                    unnecessary = ['wget', 'curl', 'git', 'ssh']
                    for pkg in unnecessary:
                        if pkg in line:
                            issues.append({
                                'line': i,
                                'severity': 'LOW',
                                'issue': f'Installing {pkg} increases attack surface',
                                'recommendation': f'Remove {pkg} if not needed'
                            })
            
            return issues
        
        def runtime_security_check(self, container_id: str) -> Dict:
            '''Check running container security'''
            
            container = self.docker_client.containers.get(container_id)
            
            security_issues = []
            
            # Check if running as root
            exec_result = container.exec_run('id -u')
            if exec_result.output.decode().strip() == '0':
                security_issues.append({
                    'type': 'runtime',
                    'severity': 'HIGH',
                    'issue': 'Container running as root'
                })
            
            # Check capabilities
            inspect = container.attrs
            if inspect['HostConfig'].get('Privileged'):
                security_issues.append({
                    'type': 'runtime',
                    'severity': 'CRITICAL',
                    'issue': 'Container running in privileged mode'
                })
            
            # Check for sensitive mounts
            for mount in inspect['Mounts']:
                if mount['Source'] in ['/etc', '/var/run/docker.sock']:
                    security_issues.append({
                        'type': 'runtime',
                        'severity': 'HIGH',
                        'issue': f'Sensitive mount: {mount["Source"]}'
                    })
            
            return {
                'container_id': container_id,
                'issues': security_issues,
                'risk_level': self.calculate_risk_level(security_issues)
            }
    """, language="python")

def secret_management_lab():
    """Secret Management in DevSecOps"""
    
    st.markdown(create_lab_header("Secret Management Lab", "🔐", "linear-gradient(90deg, #FC466B 0%, #3F5EFB 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Secret Management Theory**", expanded=True):
        st.markdown("""
        ### 🔐 **Understanding Secret Management**
        
        Secrets (passwords, API keys, tokens) are the keys to your kingdom. Poor secret management is one of the 
        leading causes of data breaches and system compromises.
        
        **Types of Secrets:**
        - 🔑 **API Keys** - Service authentication
        - 🔐 **Passwords** - Database, admin accounts
        - 📜 **Certificates** - TLS/SSL, code signing
        - 🎫 **Tokens** - OAuth, JWT, session
        - 🗝️ **SSH Keys** - Server access
        
        **Common Anti-Patterns:**
        
        1. **Hardcoded Secrets**
           - In source code
           - In configuration files
           - In container images
           - GitHub: 100K+ exposed secrets daily
        
        2. **Plain Text Storage**
           - Environment variables
           - Config files
           - Kubernetes Secrets (base64 ≠ encryption!)
        
        3. **Shared Secrets**
           - Same password everywhere
           - Shared accounts
           - Never rotated
        
        4. **Poor Access Control**
           - Everyone has prod access
           - No audit trail
           - No least privilege
        
        **Real-World Breaches:**
        - **Uber (2016)** - AWS keys in GitHub
        - **Codecov (2021)** - Env variables exposed
        - **CircleCI (2023)** - Secrets compromised
        - **LastPass (2022)** - Vault breaches
        
        **Secret Lifecycle:**
        
        **Generation:**
        - Cryptographically secure
        - Sufficient entropy
        - Unique per service
        
        **Storage:**
        - Encrypted at rest
        - Access controls
        - Audit logging
        
        **Distribution:**
        - Secure channels
        - Just-in-time access
        - Temporary credentials
        
        **Rotation:**
        - Regular rotation
        - Automated process
        - Zero downtime
        
        **Revocation:**
        - Immediate invalidation
        - Cascade to dependencies
        - Audit trail
        
        **Best Practices:**
        - Use secret management tools (Vault, AWS Secrets Manager)
        - Implement secret scanning in CI/CD
        - Use short-lived credentials
        - Enable MFA for sensitive operations
        - Regular secret rotation
        - Principle of least privilege
        - Audit all secret access
        """)
    
    # Secret Management Solutions
    st.markdown("### 🔑 **Secret Management Solutions**")
    
    solution = st.selectbox("Solution:", ["HashiCorp Vault", "AWS Secrets Manager", "Azure Key Vault", "Kubernetes Secrets"])
    
    if solution == "HashiCorp Vault":
        st.code("""
        # HashiCorp Vault Integration
        
        import hvac
        import os
        from typing import Dict, Any
        
        class VaultSecretManager:
            def __init__(self, vault_url: str, token: str = None):
                self.client = hvac.Client(url=vault_url)
                
                if token:
                    self.client.token = token
                else:
                    # Use AppRole authentication
                    self.authenticate_approle()
            
            def authenticate_approle(self):
                '''Authenticate using AppRole'''
                
                role_id = os.environ.get('VAULT_ROLE_ID')
                secret_id = os.environ.get('VAULT_SECRET_ID')
                
                response = self.client.auth.approle.login(
                    role_id=role_id,
                    secret_id=secret_id
                )
                
                self.client.token = response['auth']['client_token']
            
            def store_secret(self, path: str, secret_data: Dict[str, Any]):
                '''Store secret in Vault'''
                
                response = self.client.secrets.kv.v2.create_or_update_secret(
                    path=path,
                    secret=secret_data
                )
                
                return response
            
            def get_secret(self, path: str) -> Dict[str, Any]:
                '''Retrieve secret from Vault'''
                
                response = self.client.secrets.kv.v2.read_secret_version(
                    path=path
                )
                
                return response['data']['data']
            
            def rotate_secret(self, path: str, new_value: str):
                '''Rotate a secret'''
                
                # Get current secret
                current = self.get_secret(path)
                
                # Store as previous version
                current['previous_value'] = current.get('value')
                current['value'] = new_value
                current['rotated_at'] = datetime.now().isoformat()
                
                # Update secret
                self.store_secret(path, current)
                
                return True
            
            def create_dynamic_secret(self, backend: str, role: str):
                '''Create dynamic database credentials'''
                
                if backend == 'database':
                    response = self.client.read(f'database/creds/{role}')
                    
                    return {
                        'username': response['data']['username'],
                        'password': response['data']['password'],
                        'lease_duration': response['lease_duration']
                    }
            
            def enable_secret_engine(self, path: str, engine_type: str):
                '''Enable a secret engine'''
                
                self.client.sys.enable_secrets_engine(
                    backend_type=engine_type,
                    path=path
                )
            
            def create_policy(self, policy_name: str, policy_rules: str):
                '''Create access policy'''
                
                self.client.sys.create_or_update_policy(
                    name=policy_name,
                    policy=policy_rules
                )
        
        # CI/CD Pipeline Integration
        class PipelineSecretManager:
            def __init__(self):
                self.vault = VaultSecretManager(
                    vault_url=os.environ.get('VAULT_ADDR')
                )
            
            def inject_secrets(self, environment: str):
                '''Inject secrets into CI/CD environment'''
                
                # Get secrets for environment
                secrets = self.vault.get_secret(f'ci/{environment}')
                
                # Export as environment variables
                for key, value in secrets.items():
                    os.environ[key.upper()] = value
                
                # Mask secrets in logs
                for value in secrets.values():
                    print(f"::add-mask::{value}")
            
            def cleanup_secrets(self):
                '''Clean up secrets after use'''
                
                # Remove from environment
                secret_keys = [k for k in os.environ.keys() 
                              if k.startswith('SECRET_') or k.endswith('_KEY')]
                
                for key in secret_keys:
                    del os.environ[key]
                
                # Clear from memory
                import gc
                gc.collect()
        """, language="python")
    
    # Secret Scanning
    st.markdown("### 🔍 **Secret Scanning**")
    
    st.code("""
    # Secret Detection in Code
    
    import re
    from typing import List, Dict
    
    class SecretScanner:
        def __init__(self):
            self.patterns = {
                'aws_access_key': r'AKIA[0-9A-Z]{16}',
                'aws_secret_key': r'[0-9a-zA-Z/+=]{40}',
                'github_token': r'ghp_[a-zA-Z0-9]{36}',
                'private_key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
                'api_key': r'api[_-]?key[_-]?[=:]["\'`]?([a-zA-Z0-9]{32,})',
                'jwt': r'eyJ[a-zA-Z0-9]{10,}\\.eyJ[a-zA-Z0-9]{10,}\\.[a-zA-Z0-9_-]{10,}',
                'slack_token': r'xox[baprs]-[0-9]{10,}-[a-zA-Z0-9]{24,}',
                'generic_secret': r'(password|secret|token|apikey|api_key)["\']?\\s*[:=]\\s*["\']([^"\'\s]+)'
            }
        
        def scan_file(self, filepath: str) -> List[Dict]:
            '''Scan file for secrets'''
            
            findings = []
            
            with open(filepath, 'r') as f:
                content = f.read()
                lines = content.split('\\n')
            
            for pattern_name, pattern in self.patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE)
                
                for match in matches:
                    # Find line number
                    line_num = content[:match.start()].count('\\n') + 1
                    
                    findings.append({
                        'file': filepath,
                        'line': line_num,
                        'type': pattern_name,
                        'match': match.group()[:20] + '...',  # Truncate for safety
                        'severity': 'HIGH'
                    })
            
            return findings
        
        def scan_git_history(self, repo_path: str) -> List[Dict]:
            '''Scan git history for secrets'''
            
            import git
            
            repo = git.Repo(repo_path)
            findings = []
            
            for commit in repo.iter_commits():
                # Check commit message
                for pattern_name, pattern in self.patterns.items():
                    if re.search(pattern, commit.message):
                        findings.append({
                            'commit': commit.hexsha,
                            'author': commit.author.email,
                            'date': commit.committed_datetime,
                            'type': pattern_name,
                            'location': 'commit message'
                        })
                
                # Check diffs
                if commit.parents:
                    diffs = commit.diff(commit.parents[0])
                    
                    for diff in diffs:
                        if diff.b_blob:
                            content = diff.b_blob.data_stream.read().decode('utf-8', errors='ignore')
                            
                            for pattern_name, pattern in self.patterns.items():
                                if re.search(pattern, content):
                                    findings.append({
                                        'commit': commit.hexsha,
                                        'file': diff.b_path,
                                        'type': pattern_name,
                                        'location': 'file content'
                                    })
            
            return findings
    """, language="python")

def iac_security_lab():
    """Infrastructure as Code Security"""
    
    st.markdown(create_lab_header("IaC Security Lab", "📋", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    # IaC Security Scanning
    st.markdown("### 🔍 **IaC Security Scanning**")
    
    iac_tool = st.selectbox("IaC Tool:", ["Terraform", "CloudFormation", "Ansible", "Kubernetes"])
    
    if iac_tool == "Terraform":
        st.code("""
        # Terraform Security Scanner
        
        import json
        import subprocess
        from typing import List, Dict
        
        class TerraformSecurityScanner:
            def __init__(self):
                self.issues = []
            
            def scan_with_checkov(self, tf_dir: str) -> List[Dict]:
                '''Scan Terraform with Checkov'''
                
                try:
                    result = subprocess.run([
                        'checkov',
                        '-d', tf_dir,
                        '--framework', 'terraform',
                        '--output', 'json'
                    ], capture_output=True, text=True)
                    
                    scan_results = json.loads(result.stdout)
                    
                    findings = []
                    for check_result in scan_results.get('results', {}).get('failed_checks', []):
                        findings.append({
                            'check_id': check_result['check_id'],
                            'check_name': check_result['check_name'],
                            'file': check_result['file_path'],
                            'resource': check_result['resource'],
                            'guideline': check_result.get('guideline', ''),
                            'severity': self.map_severity(check_result['check_id'])
                        })
                    
                    return findings
                    
                except Exception as e:
                    return [{'error': str(e)}]
            
            def scan_with_tfsec(self, tf_dir: str) -> List[Dict]:
                '''Scan Terraform with tfsec'''
                
                try:
                    result = subprocess.run([
                        'tfsec', tf_dir,
                        '--format', 'json'
                    ], capture_output=True, text=True)
                    
                    scan_results = json.loads(result.stdout)
                    
                    findings = []
                    for issue in scan_results.get('results', []):
                        findings.append({
                            'rule_id': issue['rule_id'],
                            'description': issue['description'],
                            'severity': issue['severity'],
                            'file': issue['location']['filename'],
                            'line': issue['location']['start_line'],
                            'resource': issue['resource'],
                            'resolution': issue['resolution']
                        })
                    
                    return findings
                    
                except Exception as e:
                    return [{'error': str(e)}]
            
            def custom_terraform_checks(self, tf_file: str) -> List[Dict]:
                '''Custom Terraform security checks'''
                
                import hcl2
                import json
                
                findings = []
                
                with open(tf_file, 'r') as f:
                    tf_content = hcl2.load(f)
                
                # Check for hardcoded secrets
                def check_for_secrets(obj, path=''):
                    if isinstance(obj, dict):
                        for key, value in obj.items():
                            new_path = f"{path}.{key}" if path else key
                            
                            # Check key names
                            if any(secret in key.lower() for secret in 
                                  ['password', 'secret', 'token', 'key', 'api']):
                                if isinstance(value, str) and len(value) > 8:
                                    findings.append({
                                        'type': 'hardcoded_secret',
                                        'severity': 'HIGH',
                                        'path': new_path,
                                        'message': f'Potential hardcoded secret in {key}'
                                    })
                            
                            check_for_secrets(value, new_path)
                    
                    elif isinstance(obj, list):
                        for i, item in enumerate(obj):
                            check_for_secrets(item, f"{path}[{i}]")
                
                check_for_secrets(tf_content)
                
                # Check for insecure configurations
                for resource in tf_content.get('resource', []):
                    for resource_type, resources in resource.items():
                        for resource_name, config in resources.items():
                            # Check S3 buckets
                            if resource_type == 'aws_s3_bucket':
                                if not config.get('server_side_encryption_configuration'):
                                    findings.append({
                                        'type': 'missing_encryption',
                                        'severity': 'HIGH',
                                        'resource': f"{resource_type}.{resource_name}",
                                        'message': 'S3 bucket missing encryption'
                                    })
                                
                                if config.get('acl') == 'public-read':
                                    findings.append({
                                        'type': 'public_access',
                                        'severity': 'CRITICAL',
                                        'resource': f"{resource_type}.{resource_name}",
                                        'message': 'S3 bucket has public read access'
                                    })
                            
                            # Check security groups
                            elif resource_type == 'aws_security_group':
                                for rule in config.get('ingress', []):
                                    if '0.0.0.0/0' in rule.get('cidr_blocks', []):
                                        findings.append({
                                            'type': 'open_security_group',
                                            'severity': 'HIGH',
                                            'resource': f"{resource_type}.{resource_name}",
                                            'message': f'Security group open to internet on port {rule.get("from_port")}'
                                        })
                
                return findings
        
        # Terraform Security Best Practices
        class TerraformSecurity:
            @staticmethod
            def secure_backend_config():
                '''Secure Terraform backend configuration'''
                
                return '''
                terraform {
                  backend "s3" {
                    bucket         = "terraform-state-bucket"
                    key            = "prod/terraform.tfstate"
                    region         = "us-east-1"
                    encrypt        = true
                    kms_key_id     = "arn:aws:kms:us-east-1:123456789:key/abc"
                    dynamodb_table = "terraform-state-lock"
                    
                    # Version state files
                    versioning = true
                    
                    # Prevent accidental deletion
                    lifecycle {
                      prevent_destroy = true
                    }
                  }
                }
                '''
            
            @staticmethod
            def use_data_sources_for_secrets():
                '''Use data sources instead of hardcoding'''
                
                return '''
                # Good - Use AWS Secrets Manager
                data "aws_secretsmanager_secret_version" "db_password" {
                  secret_id = "prod/db/password"
                }
                
                resource "aws_db_instance" "database" {
                  password = data.aws_secretsmanager_secret_version.db_password.secret_string
                }
                
                # Good - Use environment variables
                variable "api_key" {
                  type      = string
                  sensitive = true
                }
                
                # Bad - Hardcoded secret
                # resource "aws_db_instance" "database" {
                #   password = "SuperSecret123!"  # Never do this!
                # }
                '''
        """, language="python")

def supply_chain_lab():
    """Software Supply Chain Security"""
    
    st.markdown(create_lab_header("Supply Chain Security Lab", "🔗", "linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Supply Chain Security Theory**", expanded=True):
        st.markdown("""
        ### 🔗 **Understanding Software Supply Chain Security**
        
        Software supply chain attacks target the weakest links in the development-to-deployment pipeline, 
        affecting thousands of downstream users through a single compromise.
        
        **Supply Chain Components:**
        - 📦 **Dependencies** - Third-party libraries
        - 🛠️ **Build Tools** - Compilers, CI/CD
        - 🏭 **Infrastructure** - Cloud services, CDNs
        - 👥 **Human Factor** - Developer accounts
        
        **Attack Types:**
        
        1. **Dependency Confusion**
           - Public packages override private
           - Typosquatting attacks
           - Example: npm left-pad incident
        
        2. **Malicious Packages**
           - Backdoored dependencies
           - Cryptominers in packages
           - Data exfiltration code
        
        3. **Build System Compromise**
           - Inject during compilation
           - Modify build artifacts
           - SolarWinds Orion attack
        
        4. **Update Mechanism Hijacking**
           - Compromise update servers
           - Man-in-the-middle updates
           - NotPetya via MeDoc
        
        **Major Incidents:**
        - **SolarWinds (2020)** - 18,000 organizations affected
        - **Kaseya (2021)** - 1,500+ businesses impacted
        - **Log4j (2021)** - Millions of systems vulnerable
        - **npm packages (2022)** - node-ipc sabotage
        
        **SLSA Framework (Supply chain Levels for Software Artifacts):**
        
        **Level 1: Documentation**
        - Build process documented
        - Basic provenance
        
        **Level 2: Tamper Resistance**
        - Version controlled source
        - Hosted build service
        - Signed provenance
        
        **Level 3: Security Controls**
        - Security controls on host
        - Non-falsifiable provenance
        - Isolated builds
        
        **Level 4: Highest Assurance**
        - Two-party review
        - Hermetic builds
        - Reproducible builds
        
        **Protection Strategies:**
        - Software Bill of Materials (SBOM)
        - Dependency pinning
        - Vulnerability scanning
        - Code signing & verification
        - Private registries
        - Build provenance
        - Zero-trust for artifacts
        """)
    
    # Supply Chain Security
    st.markdown("### 🔒 **Supply Chain Security**")
    
    st.code("""
    # Supply Chain Security Implementation
    
    import hashlib
    import json
    from typing import Dict, List
    import gnupg
    
    class SupplyChainSecurity:
        def __init__(self):
            self.gpg = gnupg.GPG()
            
        def generate_sbom(self, project_path: str, format: str = 'cyclonedx') -> Dict:
            '''Generate Software Bill of Materials'''
            
            components = []
            
            # Scan for dependencies
            if os.path.exists(f'{project_path}/package.json'):
                # Node.js dependencies
                with open(f'{project_path}/package.json', 'r') as f:
                    package_json = json.load(f)
                    
                    for dep, version in package_json.get('dependencies', {}).items():
                        components.append({
                            'type': 'library',
                            'name': dep,
                            'version': version,
                            'purl': f'pkg:npm/{dep}@{version}',
                            'hashes': self.get_package_hash('npm', dep, version)
                        })
            
            if os.path.exists(f'{project_path}/requirements.txt'):
                # Python dependencies
                with open(f'{project_path}/requirements.txt', 'r') as f:
                    for line in f:
                        if '==' in line:
                            name, version = line.strip().split('==')
                            components.append({
                                'type': 'library',
                                'name': name,
                                'version': version,
                                'purl': f'pkg:pypi/{name}@{version}',
                                'hashes': self.get_package_hash('pypi', name, version)
                            })
            
            sbom = {
                'bomFormat': 'CycloneDX',
                'specVersion': '1.4',
                'serialNumber': f'urn:uuid:{self.generate_uuid()}',
                'version': 1,
                'metadata': {
                    'timestamp': datetime.now().isoformat(),
                    'tools': [{'name': 'SupplyChainSecurity', 'version': '1.0'}]
                },
                'components': components
            }
            
            return sbom
        
        def sign_artifact(self, artifact_path: str, key_id: str) -> str:
            '''Sign software artifact'''
            
            with open(artifact_path, 'rb') as f:
                signed_data = self.gpg.sign_file(
                    f,
                    keyid=key_id,
                    detach=True,
                    output=f'{artifact_path}.sig'
                )
            
            if signed_data.status == 'signature created':
                return f'{artifact_path}.sig'
            else:
                raise Exception(f'Signing failed: {signed_data.status}')
        
        def verify_artifact(self, artifact_path: str, signature_path: str) -> bool:
            '''Verify artifact signature'''
            
            with open(signature_path, 'rb') as f:
                verified = self.gpg.verify_file(f, artifact_path)
            
            return verified.valid
        
        def implement_slsa(self, level: int = 3) -> Dict:
            '''Implement SLSA (Supply chain Levels for Software Artifacts)'''
            
            slsa_requirements = {
                1: {
                    'requirements': [
                        'Build process must be scripted/automated',
                        'Generate provenance'
                    ],
                    'threats_addressed': ['Mistakes', 'Basic tampering']
                },
                2: {
                    'requirements': [
                        'Version controlled sources',
                        'Hosted build service',
                        'Signed provenance'
                    ],
                    'threats_addressed': ['Source tampering', 'Build tampering']
                },
                3: {
                    'requirements': [
                        'Security controls on host',
                        'Non-falsifiable provenance',
                        'Isolated builds'
                    ],
                    'threats_addressed': ['Advanced threats', 'Dependency tampering']
                },
                4: {
                    'requirements': [
                        'Hermetic builds',
                        'Parameterless builds',
                        'Two-party review'
                    ],
                    'threats_addressed': ['All software supply chain threats']
                }
            }
            
            return slsa_requirements.get(level, {})
        
        def check_dependency_confusion(self, package_name: str, registry: str) -> Dict:
            '''Check for dependency confusion attacks'''
            
            results = {
                'package': package_name,
                'vulnerable': False,
                'recommendations': []
            }
            
            # Check if package exists in public registry
            public_exists = self.check_public_registry(package_name, registry)
            
            # Check if it's an internal package name
            if self.is_internal_package(package_name):
                if public_exists:
                    results['vulnerable'] = True
                    results['recommendations'].append(
                        'Internal package name exists in public registry - HIGH RISK'
                    )
                    results['recommendations'].append(
                        'Use scoped packages or private registry'
                    )
            
            return results
        
        def generate_provenance(self, build_info: Dict) -> Dict:
            '''Generate build provenance'''
            
            provenance = {
                '_type': 'https://in-toto.io/Statement/v0.1',
                'subject': [{
                    'name': build_info['artifact_name'],
                    'digest': {
                        'sha256': self.calculate_sha256(build_info['artifact_path'])
                    }
                }],
                'predicateType': 'https://slsa.dev/provenance/v0.2',
                'predicate': {
                    'builder': {
                        'id': build_info['builder_id']
                    },
                    'buildType': build_info['build_type'],
                    'invocation': {
                        'configSource': {
                            'uri': build_info['repo_uri'],
                            'digest': {'sha1': build_info['commit_sha']},
                            'entryPoint': build_info['build_file']
                        },
                        'parameters': build_info.get('parameters', {}),
                        'environment': build_info.get('environment', {})
                    },
                    'buildConfig': build_info.get('build_config', {}),
                    'metadata': {
                        'buildStartedOn': build_info['start_time'],
                        'buildFinishedOn': build_info['end_time'],
                        'completeness': {
                            'parameters': True,
                            'environment': True,
                            'materials': True
                        },
                        'reproducible': build_info.get('reproducible', False)
                    },
                    'materials': build_info.get('materials', [])
                }
            }
            
            return provenance
    """, language="python")
    
    # Supply Chain Metrics
    st.markdown("### 📊 **Supply Chain Security Metrics**")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("SLSA Level", "3", "↑")
        st.metric("Dependencies", "247")
    
    with col2:
        st.metric("Signed Artifacts", "100%", "✅")
        st.metric("SBOM Coverage", "95%", "+5%")
    
    with col3:
        st.metric("Vulnerable Deps", "3", "-2")
        st.metric("Provenance", "Enabled", "✅")
    
    with col4:
        st.metric("Last Audit", "2 days ago")
        st.metric("Compliance", "SOC2", "✅")

def gitops_security_lab():
    """GitOps Security"""
    
    st.markdown(create_lab_header("GitOps Security Lab", "🚀", "linear-gradient(90deg, #00C9FF 0%, #92FE9D 100%)"), unsafe_allow_html=True)
    
    st.markdown("### 🔒 **Secure GitOps Implementation**")
    
    st.code("""
    # GitOps Security with ArgoCD
    
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: argocd-rbac-cm
      namespace: argocd
    data:
      policy.default: role:readonly
      policy.csv: |
        p, role:admin, applications, *, */*, allow
        p, role:admin, clusters, *, *, allow
        p, role:developer, applications, get, */*, allow
        p, role:developer, applications, sync, */*, allow
        g, argocd-admins, role:admin
        g, developers, role:developer
    
    ---
    # Sealed Secrets for GitOps
    apiVersion: bitnami.com/v1alpha1
    kind: SealedSecret
    metadata:
      name: database-credentials
      namespace: production
    spec:
      encryptedData:
        username: AgBvA8QlG6X...
        password: AgCdKL9PqR...
    
    ---
    # OPA Policy for GitOps
    package kubernetes.admission
    
    deny[msg] {
      input.request.kind.kind == "Deployment"
      input.request.object.spec.template.spec.containers[_].image
      not starts_with(input.request.object.spec.template.spec.containers[_].image, "registry.company.com/")
      msg := "Images must be from company registry"
    }
    
    deny[msg] {
      input.request.kind.kind == "Deployment"
      not input.request.object.spec.template.spec.securityContext.runAsNonRoot
      msg := "Containers must run as non-root"
    }
    """, language="yaml")

def security_metrics_lab():
    """Security Metrics and KPIs"""
    
    st.markdown(create_lab_header("Security Metrics Lab", "📊", "linear-gradient(90deg, #FC466B 0%, #3F5EFB 100%)"), unsafe_allow_html=True)
    
    # Security Metrics Dashboard
    st.markdown("### 📈 **DevSecOps Metrics Dashboard**")
    
    # Create metrics visualization
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=("Vulnerability Trends", "MTTR by Severity", 
                       "Security Debt", "Deployment Security Score"),
        specs=[[{"type": "scatter"}, {"type": "bar"}],
               [{"type": "pie"}, {"type": "indicator"}]]
    )
    
    # Vulnerability Trends
    dates = pd.date_range(start='2024-01-01', periods=30, freq='D')
    critical = np.random.randint(0, 5, 30)
    high = np.random.randint(5, 15, 30)
    
    fig.add_trace(go.Scatter(x=dates, y=critical, name='Critical', line=dict(color='red')), row=1, col=1)
    fig.add_trace(go.Scatter(x=dates, y=high, name='High', line=dict(color='orange')), row=1, col=1)
    
    # MTTR by Severity
    severities = ['Critical', 'High', 'Medium', 'Low']
    mttr_hours = [2.5, 8.3, 24.5, 72]
    
    fig.add_trace(go.Bar(x=severities, y=mttr_hours, marker_color=['red', 'orange', 'yellow', 'green']), row=1, col=2)
    
    # Security Debt
    debt_labels = ['Fixed', 'In Progress', 'Backlog']
    debt_values = [65, 20, 15]
    
    fig.add_trace(go.Pie(labels=debt_labels, values=debt_values), row=2, col=1)
    
    # Deployment Security Score
    fig.add_trace(go.Indicator(
        mode="gauge+number",
        value=87,
        title={'text': "Security Score"},
        domain={'x': [0, 1], 'y': [0, 1]},
        gauge={'axis': {'range': [None, 100]},
               'bar': {'color': "darkgreen"},
               'steps': [
                   {'range': [0, 50], 'color': "lightgray"},
                   {'range': [50, 80], 'color': "yellow"}],
               'threshold': {'line': {'color': "red", 'width': 4},
                           'thickness': 0.75, 'value': 90}}
    ), row=2, col=2)
    
    fig.update_layout(height=600, showlegend=True)
    st.plotly_chart(fig, use_container_width=True)
    
    # Key Metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Mean Time to Detect", "4.2 hours", "-0.8")
        st.metric("False Positive Rate", "3.2%", "-0.5%")
    
    with col2:
        st.metric("Mean Time to Remediate", "12.5 hours", "-2.3")
        st.metric("Security Coverage", "94%", "+2%")
    
    with col3:
        st.metric("Vulnerabilities/Release", "2.3", "-0.7")
        st.metric("Security Gates Passed", "98.5%", "+1.2%")
    
    with col4:
        st.metric("Compliance Score", "A+", "↑")
        st.metric("Security Training", "87%", "+5%")

def automation_lab():
    """Security Automation"""
    
    st.markdown(create_lab_header("Security Automation Lab", "🤖", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    st.markdown("### 🔧 **Security Automation Framework**")
    
    st.code("""
    # Security Automation Framework
    
    import asyncio
    from typing import List, Dict, Any
    import yaml
    
    class SecurityAutomation:
        def __init__(self):
            self.playbooks = {}
            self.triggers = {}
            
        def load_playbook(self, playbook_path: str):
            '''Load security automation playbook'''
            
            with open(playbook_path, 'r') as f:
                playbook = yaml.safe_load(f)
            
            self.playbooks[playbook['name']] = playbook
            
            # Register triggers
            for trigger in playbook.get('triggers', []):
                self.register_trigger(trigger, playbook['name'])
        
        def register_trigger(self, trigger: Dict, playbook_name: str):
            '''Register event trigger'''
            
            trigger_type = trigger['type']
            
            if trigger_type not in self.triggers:
                self.triggers[trigger_type] = []
            
            self.triggers[trigger_type].append({
                'playbook': playbook_name,
                'conditions': trigger.get('conditions', []),
                'priority': trigger.get('priority', 5)
            })
        
        async def handle_event(self, event: Dict):
            '''Handle security event'''
            
            event_type = event['type']
            
            # Find matching triggers
            matching_triggers = self.triggers.get(event_type, [])
            
            # Sort by priority
            matching_triggers.sort(key=lambda x: x['priority'])
            
            # Execute playbooks
            for trigger in matching_triggers:
                if self.evaluate_conditions(trigger['conditions'], event):
                    await self.execute_playbook(trigger['playbook'], event)
        
        async def execute_playbook(self, playbook_name: str, context: Dict):
            '''Execute security playbook'''
            
            playbook = self.playbooks[playbook_name]
            
            print(f"Executing playbook: {playbook_name}")
            
            for step in playbook['steps']:
                step_type = step['type']
                
                if step_type == 'scan':
                    await self.execute_scan(step, context)
                elif step_type == 'remediate':
                    await self.execute_remediation(step, context)
                elif step_type == 'notify':
                    await self.send_notification(step, context)
                elif step_type == 'isolate':
                    await self.isolate_resource(step, context)
                elif step_type == 'block':
                    await self.block_threat(step, context)
        
        async def execute_scan(self, step: Dict, context: Dict):
            '''Execute security scan'''
            
            scan_type = step['scan_type']
            target = self.resolve_target(step['target'], context)
            
            if scan_type == 'vulnerability':
                result = await self.vulnerability_scan(target)
            elif scan_type == 'malware':
                result = await self.malware_scan(target)
            elif scan_type == 'compliance':
                result = await self.compliance_scan(target)
            
            # Store results in context
            context['scan_results'] = result
            
            return result
        
        async def execute_remediation(self, step: Dict, context: Dict):
            '''Execute automated remediation'''
            
            remediation_type = step['remediation_type']
            
            if remediation_type == 'patch':
                await self.apply_patch(step['patch_id'], context['target'])
            elif remediation_type == 'configuration':
                await self.update_configuration(step['config'], context['target'])
            elif remediation_type == 'rollback':
                await self.rollback_deployment(context['deployment_id'])
    
    # Example Playbook
    example_playbook = '''
    name: critical_vulnerability_response
    description: Automated response to critical vulnerabilities
    
    triggers:
      - type: vulnerability_detected
        conditions:
          - field: severity
            operator: equals
            value: critical
        priority: 1
    
    steps:
      - type: scan
        scan_type: vulnerability
        target: "{{ affected_system }}"
        
      - type: isolate
        target: "{{ affected_system }}"
        method: network_isolation
        
      - type: notify
        channels:
          - slack
          - email
        recipients:
          - security-team
          - ops-team
        template: critical_vulnerability_alert
        
      - type: remediate
        remediation_type: patch
        patch_id: "{{ cve_id }}"
        approval_required: false
        
      - type: verify
        verification_type: scan
        expected_result: no_vulnerability
        
      - type: restore
        target: "{{ affected_system }}"
        method: restore_network_access
    '''
    """, language="python")

def policy_as_code_lab():
    """Policy as Code"""
    
    st.markdown(create_lab_header("Policy as Code Lab", "🛡️", "linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)"), unsafe_allow_html=True)
    
    st.markdown("### 📋 **Policy as Code Implementation**")
    
    policy_engine = st.selectbox("Policy Engine:", ["Open Policy Agent (OPA)", "Sentinel", "Polaris", "Falco"])
    
    if policy_engine == "Open Policy Agent (OPA)":
        st.code("""
        # OPA Policies for DevSecOps
        
        package devsecops.security
        
        # Deny containers running as root
        deny[msg] {
            input.kind == "Deployment"
            container := input.spec.template.spec.containers[_]
            container.securityContext.runAsUser == 0
            msg := sprintf("Container '%s' is running as root", [container.name])
        }
        
        # Deny images without digest
        deny[msg] {
            input.kind == "Deployment"
            container := input.spec.template.spec.containers[_]
            not contains(container.image, "@sha256:")
            msg := sprintf("Container '%s' image must use digest", [container.name])
        }
        
        # Require security scanning labels
        deny[msg] {
            input.kind == "Deployment"
            not input.metadata.labels["security.scan"]
            msg := "Deployment must have security.scan label"
        }
        
        # Enforce resource limits
        deny[msg] {
            input.kind == "Deployment"
            container := input.spec.template.spec.containers[_]
            not container.resources.limits.memory
            msg := sprintf("Container '%s' must have memory limits", [container.name])
        }
        
        # Require network policies
        require_network_policy[msg] {
            input.kind == "Deployment"
            namespace := input.metadata.namespace
            not network_policy_exists(namespace)
            msg := sprintf("Namespace '%s' must have NetworkPolicy", [namespace])
        }
        
        # Helper function
        network_policy_exists(namespace) {
            some i
            data.kubernetes.networkpolicies[namespace][i]
        }
        
        # Vulnerability threshold policy
        deny[msg] {
            input.vulnerability_scan.critical_count > 0
            msg := sprintf("Image has %d critical vulnerabilities", [input.vulnerability_scan.critical_count])
        }
        
        deny[msg] {
            input.vulnerability_scan.high_count > 5
            msg := sprintf("Image has %d high vulnerabilities (max: 5)", [input.vulnerability_scan.high_count])
        }
        
        # License compliance
        deny[msg] {
            input.sbom.licenses[_] == "GPL-3.0"
            msg := "GPL-3.0 licensed dependencies not allowed"
        }
        
        # Supply chain policy
        deny[msg] {
            not input.provenance
            msg := "Artifact must have provenance"
        }
        
        deny[msg] {
            input.provenance.slsa_level < 3
            msg := sprintf("SLSA level %d insufficient (minimum: 3)", [input.provenance.slsa_level])
        }
        """, language="rego")
    
    # Policy Testing
    st.markdown("### 🧪 **Policy Testing**")
    
    st.code("""
    # Test OPA Policies
    
    package devsecops.security_test
    
    test_deny_root_container {
        deny[_] with input as {
            "kind": "Deployment",
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "app",
                            "securityContext": {
                                "runAsUser": 0
                            }
                        }]
                    }
                }
            }
        }
    }
    
    test_allow_non_root_container {
        count(deny) == 0 with input as {
            "kind": "Deployment",
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "app",
                            "securityContext": {
                                "runAsUser": 1000
                            }
                        }]
                    }
                }
            }
        }
    }
    """, language="rego")
    
    # Policy Metrics
    st.markdown("### 📊 **Policy Enforcement Metrics**")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Policies Defined", "47")
        st.metric("Active Policies", "45", "95.7%")
    
    with col2:
        st.metric("Violations Today", "12", "+3")
        st.metric("Auto-Remediated", "8", "66.7%")
    
    with col3:
        st.metric("Policy Coverage", "92%", "+2%")
        st.metric("False Positives", "2", "-1")
    
    with col4:
        st.metric("Compliance", "✅ Passed")
        st.metric("Last Audit", "1 hour ago")

if __name__ == "__main__":
    run_lab()
