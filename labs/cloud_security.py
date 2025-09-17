"""
Cloud Security Lab
Security in cloud environments (AWS, Azure, GCP, Kubernetes)
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
    """Cloud Security Lab - Securing Cloud Infrastructure & Services"""
    
    # Compact Header
    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 1rem; border-radius: 8px; margin-bottom: 1rem; text-align: center;">
        <h2 style="color: white; margin: 0; font-size: 1.5rem;">
            ☁️ Cloud Security Lab
        </h2>
        <p style="color: white; margin: 0; font-size: 0.9rem; opacity: 0.9;">
            AWS, Azure, GCP, Kubernetes & Container Security
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Cloud Security topics tabs
    tabs = st.tabs([
        "☁️ Multi-Cloud",
        "🔐 IAM & Zero Trust",
        "🚨 Misconfigurations",
        "📦 Container Security",
        "🎯 Kubernetes",
        "⚡ Serverless",
        "🔍 CSPM",
        "🛡️ CWPP",
        "🌐 API Gateway",
        "💾 Data Security",
        "📊 Compliance",
        "🚀 DevSecOps Cloud"
    ])
    
    with tabs[0]:
        multi_cloud_lab()
    
    with tabs[1]:
        iam_zero_trust_lab()
    
    with tabs[2]:
        misconfigurations_lab()
    
    with tabs[3]:
        container_security_lab()
    
    with tabs[4]:
        kubernetes_security_lab()
    
    with tabs[5]:
        serverless_security_lab()
    
    with tabs[6]:
        cspm_lab()
    
    with tabs[7]:
        cwpp_lab()
    
    with tabs[8]:
        api_gateway_lab()
    
    with tabs[9]:
        data_security_lab()
    
    with tabs[10]:
        compliance_lab()
    
    with tabs[11]:
        devsecops_cloud_lab()

def multi_cloud_lab():
    """Multi-Cloud Security Management"""
    
    st.markdown(create_lab_header("Multi-Cloud Security Lab", "☁️", "linear-gradient(90deg, #FF6B6B 0%, #4ECDC4 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Multi-Cloud Security Theory**", expanded=True):
        st.markdown("""
        ### ☁️ **Understanding Multi-Cloud Security**
        
        Multi-cloud strategy involves using services from multiple cloud providers (AWS, Azure, GCP) to avoid 
        vendor lock-in, optimize costs, and improve resilience. However, it introduces unique security challenges.
        
        **Why Multi-Cloud?**
        - 🔄 **Avoid Vendor Lock-in** - Freedom to switch providers
        - 💰 **Cost Optimization** - Use best pricing for each service
        - 🌍 **Geographic Coverage** - Better global presence
        - 🛡️ **Risk Mitigation** - No single point of failure
        
        **Security Challenges:**
        
        1. **Complexity Management**
           - Different security models per provider
           - Inconsistent APIs and tools
           - Multiple dashboards and alerts
           - Skills gap across platforms
        
        2. **Identity & Access Management**
           - Different IAM systems (AWS IAM, Azure AD, GCP IAM)
           - Federation challenges
           - Cross-cloud authentication
           - Privilege escalation risks
        
        3. **Data Protection**
           - Data residency requirements
           - Encryption key management
           - Cross-cloud data transfer security
           - Compliance across jurisdictions
        
        4. **Network Security**
           - Inter-cloud connectivity
           - Different network models
           - Inconsistent security groups/firewalls
           - Attack surface expansion
        
        **Common Vulnerabilities:**
        - 🔓 Misconfigured storage buckets (S3, Blob, GCS)
        - 🔑 Exposed API keys and credentials
        - 🌐 Open security groups/network ACLs
        - 💾 Unencrypted data at rest/transit
        - 👤 Excessive IAM permissions
        
        **Best Practices:**
        - Centralized security monitoring (SIEM)
        - Cloud Security Posture Management (CSPM)
        - Infrastructure as Code (IaC)
        - Zero Trust architecture
        - Regular security assessments
        """)
    
    # Cloud Provider Selection
    provider = st.selectbox("Cloud Provider:", ["AWS", "Azure", "GCP", "Multi-Cloud"])
    
    if provider == "AWS":
        st.markdown("### 🔶 **AWS Security**")
        
        service = st.selectbox("AWS Service:", ["EC2", "S3", "IAM", "VPC", "Lambda"])
        
        if service == "S3":
            st.markdown("#### **S3 Bucket Security**")
            
            st.code("""
            # S3 Bucket Security Configuration
            
            import boto3
            import json
            
            class S3SecurityAuditor:
                def __init__(self):
                    self.s3 = boto3.client('s3')
                    self.s3_resource = boto3.resource('s3')
                    
                def audit_bucket(self, bucket_name):
                    '''Comprehensive S3 bucket security audit'''
                    
                    findings = {
                        'bucket': bucket_name,
                        'issues': [],
                        'risk_level': 'Low'
                    }
                    
                    # Check public access
                    try:
                        acl = self.s3.get_bucket_acl(Bucket=bucket_name)
                        for grant in acl['Grants']:
                            grantee = grant.get('Grantee', {})
                            if grantee.get('Type') == 'Group':
                                if 'AllUsers' in grantee.get('URI', ''):
                                    findings['issues'].append({
                                        'type': 'public_read',
                                        'severity': 'Critical',
                                        'details': 'Bucket allows public read access'
                                    })
                                    findings['risk_level'] = 'Critical'
                    except Exception as e:
                        findings['issues'].append({'error': str(e)})
                    
                    # Check encryption
                    try:
                        encryption = self.s3.get_bucket_encryption(Bucket=bucket_name)
                    except:
                        findings['issues'].append({
                            'type': 'no_encryption',
                            'severity': 'High',
                            'details': 'Bucket encryption not enabled'
                        })
                        findings['risk_level'] = max(findings['risk_level'], 'High')
                    
                    # Check versioning
                    versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        findings['issues'].append({
                            'type': 'no_versioning',
                            'severity': 'Medium',
                            'details': 'Versioning not enabled'
                        })
                    
                    # Check logging
                    try:
                        logging = self.s3.get_bucket_logging(Bucket=bucket_name)
                        if 'LoggingEnabled' not in logging:
                            findings['issues'].append({
                                'type': 'no_logging',
                                'severity': 'Medium',
                                'details': 'Access logging not enabled'
                            })
                    except:
                        pass
                    
                    # Check bucket policy
                    try:
                        policy = self.s3.get_bucket_policy(Bucket=bucket_name)
                        policy_json = json.loads(policy['Policy'])
                        
                        # Check for overly permissive policies
                        for statement in policy_json.get('Statement', []):
                            if statement.get('Effect') == 'Allow':
                                if statement.get('Principal') == '*':
                                    findings['issues'].append({
                                        'type': 'permissive_policy',
                                        'severity': 'High',
                                        'details': 'Bucket policy allows public access'
                                    })
                    except:
                        pass
                    
                    return findings
                
                def remediate_bucket(self, bucket_name, findings):
                    '''Apply security remediations'''
                    
                    remediations = []
                    
                    for issue in findings['issues']:
                        if issue['type'] == 'public_read':
                            # Block public access
                            self.s3.put_public_access_block(
                                Bucket=bucket_name,
                                PublicAccessBlockConfiguration={
                                    'BlockPublicAcls': True,
                                    'IgnorePublicAcls': True,
                                    'BlockPublicPolicy': True,
                                    'RestrictPublicBuckets': True
                                }
                            )
                            remediations.append('Blocked public access')
                        
                        elif issue['type'] == 'no_encryption':
                            # Enable encryption
                            self.s3.put_bucket_encryption(
                                Bucket=bucket_name,
                                ServerSideEncryptionConfiguration={
                                    'Rules': [{
                                        'ApplyServerSideEncryptionByDefault': {
                                            'SSEAlgorithm': 'AES256'
                                        }
                                    }]
                                }
                            )
                            remediations.append('Enabled encryption')
                        
                        elif issue['type'] == 'no_versioning':
                            # Enable versioning
                            self.s3.put_bucket_versioning(
                                Bucket=bucket_name,
                                VersioningConfiguration={'Status': 'Enabled'}
                            )
                            remediations.append('Enabled versioning')
                    
                    return remediations
            """, language="python")
            
    elif provider == "Azure":
        st.markdown("### 🔷 **Azure Security**")
        
        st.code("""
        # Azure Security Center Integration
        
        from azure.mgmt.security import SecurityCenter
        from azure.identity import DefaultAzureCredential
        
        class AzureSecurityManager:
            def __init__(self, subscription_id):
                self.credential = DefaultAzureCredential()
                self.security_client = SecurityCenter(
                    self.credential, 
                    subscription_id
                )
                
            def get_security_score(self):
                '''Get Azure Secure Score'''
                scores = self.security_client.secure_scores.list()
                
                for score in scores:
                    return {
                        'score': score.score.current,
                        'max_score': score.score.max,
                        'percentage': (score.score.current / score.score.max) * 100
                    }
            
            def get_recommendations(self):
                '''Get security recommendations'''
                recommendations = self.security_client.assessments.list()
                
                critical_recommendations = []
                for rec in recommendations:
                    if rec.status.code == 'Unhealthy':
                        critical_recommendations.append({
                            'name': rec.display_name,
                            'severity': rec.metadata.severity,
                            'description': rec.metadata.description,
                            'remediation': rec.metadata.remediation_description
                        })
                
                return critical_recommendations
            
            def enable_azure_defender(self, resource_type='VirtualMachines'):
                '''Enable Azure Defender for resources'''
                pricing = self.security_client.pricings.update(
                    pricing_name=resource_type,
                    pricing={
                        'pricing_tier': 'Standard'
                    }
                )
                return pricing
        """, language="python")
    
    elif provider == "GCP":
        st.markdown("### 🔵 **Google Cloud Security**")
        
        st.code("""
        # GCP Security Command Center
        
        from google.cloud import securitycenter
        
        class GCPSecurityScanner:
            def __init__(self, project_id):
                self.client = securitycenter.SecurityCenterClient()
                self.project_id = project_id
                self.parent = f"projects/{project_id}"
                
            def list_findings(self):
                '''List security findings'''
                
                # Filter for active findings
                filter_query = 'state="ACTIVE"'
                
                findings = self.client.list_findings(
                    request={
                        "parent": f"{self.parent}/sources/-",
                        "filter": filter_query
                    }
                )
                
                high_priority_findings = []
                for finding in findings:
                    if finding.severity in ['CRITICAL', 'HIGH']:
                        high_priority_findings.append({
                            'name': finding.name,
                            'category': finding.category,
                            'severity': finding.severity,
                            'resource': finding.resource_name,
                            'recommendation': finding.finding.source_properties
                        })
                
                return high_priority_findings
            
            def create_security_mark(self, finding_name, key, value):
                '''Mark findings for tracking'''
                
                security_marks = self.client.update_security_marks(
                    request={
                        "security_marks": {
                            "name": f"{finding_name}/securityMarks",
                            "marks": {key: value}
                        }
                    }
                )
                return security_marks
        """, language="python")
    
    # Multi-Cloud Dashboard
    st.markdown("### 📊 **Multi-Cloud Security Dashboard**")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("AWS Security Score", "87/100", "+3")
        st.metric("Critical Issues", "2", "-1")
    
    with col2:
        st.metric("Azure Security Score", "92/100", "+5")
        st.metric("Recommendations", "14", "+2")
    
    with col3:
        st.metric("GCP Security Score", "89/100", "+2")
        st.metric("Active Findings", "7", "-3")

def iam_zero_trust_lab():
    """IAM and Zero Trust Architecture"""
    
    st.markdown(create_lab_header("IAM & Zero Trust Lab", "🔐", "linear-gradient(90deg, #667eea 0%, #764ba2 100%)"), unsafe_allow_html=True)
    
    # Zero Trust Principles
    st.markdown("### 🎯 **Zero Trust Architecture**")
    
    with st.expander("📖 **Zero Trust Principles**", expanded=True):
        st.markdown("""
        **Core Principles:**
        1. **Never Trust, Always Verify** - No implicit trust
        2. **Least Privilege Access** - Minimal required permissions
        3. **Assume Breach** - Design for compromised environment
        4. **Verify Explicitly** - Authenticate and authorize every transaction
        5. **Microsegmentation** - Limit lateral movement
        """)
    
    # IAM Policy Generator
    st.markdown("### 📝 **IAM Policy Generator**")
    
    policy_type = st.selectbox("Policy Type:", ["AWS IAM", "Azure RBAC", "GCP IAM"])
    
    if policy_type == "AWS IAM":
        resource = st.text_input("Resource ARN:", "arn:aws:s3:::my-bucket/*")
        actions = st.multiselect("Actions:", ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"])
        
        if st.button("Generate Policy", key="gen_iam"):
            policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": actions,
                    "Resource": resource,
                    "Condition": {
                        "IpAddress": {
                            "aws:SourceIp": ["10.0.0.0/8"]
                        },
                        "StringEquals": {
                            "aws:userid": "AIDAI23HXD2O5EXAMPLE"
                        }
                    }
                }]
            }
            
            st.code(json.dumps(policy, indent=2), language="json")
    
    # Least Privilege Analysis
    st.markdown("### 🔍 **Least Privilege Analysis**")
    
    st.code("""
    import boto3
    from datetime import datetime, timedelta
    
    class LeastPrivilegeAnalyzer:
        def __init__(self):
            self.iam = boto3.client('iam')
            self.cloudtrail = boto3.client('cloudtrail')
            
        def analyze_user_permissions(self, username):
            '''Analyze user's actual vs granted permissions'''
            
            # Get user's policies
            granted_permissions = self.get_user_permissions(username)
            
            # Get actually used permissions from CloudTrail
            used_permissions = self.get_used_permissions(username)
            
            # Find unused permissions
            unused_permissions = set(granted_permissions) - set(used_permissions)
            
            # Calculate risk score
            risk_score = self.calculate_risk_score(unused_permissions)
            
            return {
                'user': username,
                'granted': len(granted_permissions),
                'used': len(used_permissions),
                'unused': list(unused_permissions),
                'risk_score': risk_score,
                'recommendations': self.generate_recommendations(unused_permissions)
            }
        
        def get_user_permissions(self, username):
            '''Get all permissions for a user'''
            permissions = set()
            
            # Get inline policies
            inline_policies = self.iam.list_user_policies(UserName=username)
            for policy_name in inline_policies['PolicyNames']:
                policy = self.iam.get_user_policy(
                    UserName=username,
                    PolicyName=policy_name
                )
                permissions.update(self.extract_actions(policy['PolicyDocument']))
            
            # Get attached policies
            attached_policies = self.iam.list_attached_user_policies(UserName=username)
            for policy in attached_policies['AttachedPolicies']:
                policy_version = self.iam.get_policy_version(
                    PolicyArn=policy['PolicyArn'],
                    VersionId=self.iam.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
                )
                permissions.update(self.extract_actions(policy_version['PolicyVersion']['Document']))
            
            # Get group policies
            groups = self.iam.list_groups_for_user(UserName=username)
            for group in groups['Groups']:
                group_policies = self.iam.list_attached_group_policies(GroupName=group['GroupName'])
                for policy in group_policies['AttachedPolicies']:
                    # Process group policies...
                    pass
            
            return permissions
        
        def get_used_permissions(self, username, days=90):
            '''Get permissions actually used by user from CloudTrail'''
            
            end_time = datetime.now()
            start_time = end_time - timedelta(days=days)
            
            used_actions = set()
            
            events = self.cloudtrail.lookup_events(
                LookupAttributes=[{
                    'AttributeKey': 'Username',
                    'AttributeValue': username
                }],
                StartTime=start_time,
                EndTime=end_time
            )
            
            for event in events['Events']:
                # Extract action from event
                event_name = event.get('EventName', '')
                service = event.get('EventSource', '').replace('.amazonaws.com', '')
                
                if service and event_name:
                    action = f"{service}:{event_name}"
                    used_actions.add(action)
            
            return used_actions
        
        def generate_recommendations(self, unused_permissions):
            '''Generate security recommendations'''
            
            recommendations = []
            
            # High-risk permissions
            high_risk = ['iam:*', 's3:DeleteBucket', 'ec2:TerminateInstances']
            
            for perm in unused_permissions:
                if any(risk in perm for risk in high_risk):
                    recommendations.append({
                        'action': 'remove',
                        'permission': perm,
                        'reason': 'High-risk unused permission',
                        'priority': 'Critical'
                    })
                else:
                    recommendations.append({
                        'action': 'review',
                        'permission': perm,
                        'reason': 'Unused permission',
                        'priority': 'Medium'
                    })
            
            return recommendations
    """, language="python")
    
    # Zero Trust Implementation
    st.markdown("### 🛡️ **Zero Trust Implementation**")
    
    implementation = st.selectbox("Implementation Phase:", ["Identity", "Device", "Network", "Application", "Data"])
    
    if implementation == "Identity":
        st.code("""
        # Identity-based Zero Trust
        
        class ZeroTrustIdentity:
            def __init__(self):
                self.mfa_required = True
                self.session_timeout = 3600  # 1 hour
                self.risk_threshold = 0.7
                
            def authenticate_user(self, username, password, context):
                '''Multi-factor authentication with risk assessment'''
                
                # Step 1: Password verification
                if not self.verify_password(username, password):
                    return False, "Invalid credentials"
                
                # Step 2: Risk assessment
                risk_score = self.assess_risk(username, context)
                
                if risk_score > self.risk_threshold:
                    # Step 3: Require additional verification
                    mfa_required = True
                    verification_methods = ['sms', 'totp', 'biometric']
                else:
                    mfa_required = self.mfa_required
                    verification_methods = ['totp']
                
                # Step 4: MFA verification
                if mfa_required:
                    mfa_result = self.verify_mfa(username, verification_methods)
                    if not mfa_result:
                        return False, "MFA verification failed"
                
                # Step 5: Create limited session
                session = self.create_session(username, risk_score)
                
                return True, session
            
            def assess_risk(self, username, context):
                '''Assess authentication risk based on context'''
                
                risk_factors = {
                    'new_device': 0.3,
                    'unusual_location': 0.4,
                    'unusual_time': 0.2,
                    'impossible_travel': 0.9,
                    'known_vpn': -0.1,
                    'corporate_network': -0.3
                }
                
                risk_score = 0.0
                
                # Check each risk factor
                if self.is_new_device(username, context['device_id']):
                    risk_score += risk_factors['new_device']
                
                if self.is_unusual_location(username, context['location']):
                    risk_score += risk_factors['unusual_location']
                
                if self.is_unusual_time(username, context['timestamp']):
                    risk_score += risk_factors['unusual_time']
                
                # Normalize score
                risk_score = max(0, min(1, risk_score))
                
                return risk_score
        """, language="python")

def misconfigurations_lab():
    """Cloud Misconfigurations Detection"""
    
    st.markdown(create_lab_header("Misconfigurations Lab", "🚨", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    # Common Misconfigurations
    st.markdown("### ⚠️ **Common Cloud Misconfigurations**")
    
    misconfig_type = st.selectbox("Misconfiguration Type:", [
        "Public S3 Buckets", 
        "Open Security Groups", 
        "Unencrypted Databases", 
        "Excessive IAM Permissions",
        "Public Snapshots"
    ])
    
    if misconfig_type == "Open Security Groups":
        st.code("""
        import boto3
        
        class SecurityGroupAuditor:
            def __init__(self):
                self.ec2 = boto3.client('ec2')
                
            def find_open_security_groups(self):
                '''Find security groups with 0.0.0.0/0 access'''
                
                response = self.ec2.describe_security_groups()
                vulnerable_groups = []
                
                for sg in response['SecurityGroups']:
                    for rule in sg.get('IpPermissions', []):
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                # Check if it's a sensitive port
                                from_port = rule.get('FromPort', 0)
                                to_port = rule.get('ToPort', 65535)
                                
                                sensitive_ports = [22, 3389, 3306, 5432, 27017, 6379]
                                
                                for port in sensitive_ports:
                                    if from_port <= port <= to_port:
                                        vulnerable_groups.append({
                                            'group_id': sg['GroupId'],
                                            'group_name': sg['GroupName'],
                                            'port': port,
                                            'protocol': rule.get('IpProtocol'),
                                            'severity': 'CRITICAL',
                                            'recommendation': f'Restrict access to port {port}'
                                        })
                                        break
                
                return vulnerable_groups
            
            def remediate_security_group(self, group_id, port):
                '''Remove public access from security group'''
                
                try:
                    # Revoke public access
                    self.ec2.revoke_security_group_ingress(
                        GroupId=group_id,
                        IpPermissions=[{
                            'IpProtocol': 'tcp',
                            'FromPort': port,
                            'ToPort': port,
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }]
                    )
                    
                    # Add restricted access (example: only from VPN)
                    self.ec2.authorize_security_group_ingress(
                        GroupId=group_id,
                        IpPermissions=[{
                            'IpProtocol': 'tcp',
                            'FromPort': port,
                            'ToPort': port,
                            'IpRanges': [{'CidrIp': '10.0.0.0/8', 'Description': 'Corporate VPN'}]
                        }]
                    )
                    
                    return True, "Security group remediated successfully"
                    
                except Exception as e:
                    return False, str(e)
        
        # Automated misconfiguration scanner
        class CloudMisconfigScanner:
            def __init__(self):
                self.checks = {
                    's3': self.check_s3_buckets,
                    'ec2': self.check_ec2_instances,
                    'rds': self.check_rds_databases,
                    'iam': self.check_iam_policies,
                    'kms': self.check_kms_keys
                }
                
            def run_full_scan(self):
                '''Run comprehensive misconfiguration scan'''
                
                findings = {
                    'critical': [],
                    'high': [],
                    'medium': [],
                    'low': []
                }
                
                for service, check_func in self.checks.items():
                    service_findings = check_func()
                    
                    for finding in service_findings:
                        severity = finding['severity'].lower()
                        findings[severity].append(finding)
                
                # Generate report
                report = self.generate_report(findings)
                
                return findings, report
            
            def check_s3_buckets(self):
                '''Check S3 bucket misconfigurations'''
                s3 = boto3.client('s3')
                findings = []
                
                buckets = s3.list_buckets()
                
                for bucket in buckets['Buckets']:
                    bucket_name = bucket['Name']
                    
                    # Check public access
                    try:
                        acl = s3.get_bucket_acl(Bucket=bucket_name)
                        for grant in acl['Grants']:
                            if 'AllUsers' in grant.get('Grantee', {}).get('URI', ''):
                                findings.append({
                                    'service': 'S3',
                                    'resource': bucket_name,
                                    'issue': 'Public read access enabled',
                                    'severity': 'CRITICAL',
                                    'remediation': 'Block public access'
                                })
                    except:
                        pass
                    
                    # Check encryption
                    try:
                        s3.get_bucket_encryption(Bucket=bucket_name)
                    except:
                        findings.append({
                            'service': 'S3',
                            'resource': bucket_name,
                            'issue': 'Encryption not enabled',
                            'severity': 'HIGH',
                            'remediation': 'Enable default encryption'
                        })
                    
                    # Check versioning
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        findings.append({
                            'service': 'S3',
                            'resource': bucket_name,
                            'issue': 'Versioning not enabled',
                            'severity': 'MEDIUM',
                            'remediation': 'Enable versioning for data recovery'
                        })
                
                return findings
        """, language="python")
    
    # Misconfiguration Dashboard
    st.markdown("### 📊 **Misconfiguration Dashboard**")
    
    # Simulate scan results
    misconfigs = {
        "Type": ["Public S3", "Open Ports", "Weak Passwords", "No MFA", "Unencrypted Data"],
        "Count": [3, 7, 12, 25, 5],
        "Severity": ["Critical", "Critical", "High", "High", "Critical"]
    }
    
    df = pd.DataFrame(misconfigs)
    
    fig = px.bar(df, x="Type", y="Count", color="Severity",
                 title="Cloud Misconfigurations by Type",
                 color_discrete_map={"Critical": "red", "High": "orange", "Medium": "yellow"})
    st.plotly_chart(fig, use_container_width=True)

def container_security_lab():
    """Container and Docker Security"""
    
    st.markdown(create_lab_header("Container Security Lab", "📦", "linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Container Security Theory**", expanded=True):
        st.markdown("""
        ### 📦 **Understanding Container Security**
        
        Containers revolutionized application deployment but introduced new security challenges. Unlike VMs, 
        containers share the host kernel, creating unique attack vectors.
        
        **Container Architecture Risks:**
        - 🔄 **Shared Kernel** - Container escape to host
        - 📚 **Image Layers** - Vulnerabilities in base images
        - 🔑 **Secrets Management** - Hardcoded credentials
        - 🌐 **Network Exposure** - Container-to-container attacks
        
        **Common Container Vulnerabilities:**
        
        1. **Image Vulnerabilities**
           - Outdated base images
           - Known CVEs in packages
           - Malicious images from untrusted sources
           - Supply chain attacks
        
        2. **Runtime Risks**
           - Running as root (UID 0)
           - Privileged containers
           - Excessive capabilities
           - Host filesystem mounts
        
        3. **Configuration Issues**
           - Exposed Docker socket
           - Insecure registries
           - Missing resource limits
           - No network segmentation
        
        4. **Secret Exposure**
           - Hardcoded passwords in images
           - Environment variables with secrets
           - Secrets in container logs
           - Unencrypted secret storage
        
        **Attack Vectors:**
        - 🎯 **Container Breakout** - Escape to host system
        - 💉 **Image Poisoning** - Malicious base images
        - 🔓 **Privilege Escalation** - Root access in container
        - 🌐 **Lateral Movement** - Container-to-container
        - 📊 **Data Theft** - Access to mounted volumes
        
        **Defense Strategies:**
        - Image scanning (Trivy, Clair, Anchore)
        - Runtime protection (Falco, Sysdig)
        - Network policies & segmentation
        - Secrets management (Vault, Kubernetes Secrets)
        - Security policies (PodSecurityPolicy, OPA)
        - Minimal base images (distroless, Alpine)
        - Regular updates & patches
        """)
    
    # Container Security Scanning
    st.markdown("### 🔍 **Container Security Scanning**")
    
    st.code("""
    import docker
    import json
    import subprocess
    
    class ContainerSecurityScanner:
        def __init__(self):
            self.docker_client = docker.from_env()
            
        def scan_image(self, image_name):
            '''Scan Docker image for vulnerabilities'''
            
            findings = {
                'image': image_name,
                'vulnerabilities': [],
                'misconfigurations': [],
                'secrets': []
            }
            
            # Pull image if needed
            try:
                image = self.docker_client.images.get(image_name)
            except:
                image = self.docker_client.images.pull(image_name)
            
            # Scan with Trivy
            trivy_scan = self.run_trivy_scan(image_name)
            findings['vulnerabilities'] = trivy_scan
            
            # Check Dockerfile best practices
            dockerfile_issues = self.check_dockerfile(image)
            findings['misconfigurations'] = dockerfile_issues
            
            # Scan for secrets
            secrets = self.scan_for_secrets(image)
            findings['secrets'] = secrets
            
            # Calculate risk score
            findings['risk_score'] = self.calculate_risk_score(findings)
            
            return findings
        
        def run_trivy_scan(self, image_name):
            '''Run Trivy vulnerability scanner'''
            
            try:
                result = subprocess.run(
                    ['trivy', 'image', '--format', 'json', image_name],
                    capture_output=True,
                    text=True
                )
                
                scan_results = json.loads(result.stdout)
                
                vulnerabilities = []
                for result in scan_results.get('Results', []):
                    for vuln in result.get('Vulnerabilities', []):
                        vulnerabilities.append({
                            'id': vuln['VulnerabilityID'],
                            'package': vuln['PkgName'],
                            'severity': vuln['Severity'],
                            'title': vuln.get('Title', ''),
                            'fixed_version': vuln.get('FixedVersion', 'No fix available')
                        })
                
                return vulnerabilities
                
            except Exception as e:
                return [{'error': str(e)}]
        
        def check_dockerfile(self, image):
            '''Check for Dockerfile best practices'''
            
            issues = []
            
            # Get image history
            history = image.history()
            
            # Check for running as root
            config = image.attrs['Config']
            if not config.get('User'):
                issues.append({
                    'type': 'running_as_root',
                    'severity': 'HIGH',
                    'description': 'Container runs as root user',
                    'remediation': 'Add USER directive to Dockerfile'
                })
            
            # Check for latest tag
            for tag in image.tags:
                if ':latest' in tag:
                    issues.append({
                        'type': 'latest_tag',
                        'severity': 'MEDIUM',
                        'description': 'Using latest tag',
                        'remediation': 'Use specific version tags'
                    })
            
            # Check for exposed sensitive ports
            exposed_ports = config.get('ExposedPorts', {})
            sensitive_ports = ['22/tcp', '23/tcp', '3389/tcp']
            
            for port in sensitive_ports:
                if port in exposed_ports:
                    issues.append({
                        'type': 'sensitive_port_exposed',
                        'severity': 'HIGH',
                        'description': f'Sensitive port {port} exposed',
                        'remediation': f'Remove EXPOSE {port} from Dockerfile'
                    })
            
            # Check for hardcoded secrets in environment
            env_vars = config.get('Env', [])
            secret_patterns = ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'API']
            
            for env in env_vars:
                for pattern in secret_patterns:
                    if pattern in env.upper():
                        issues.append({
                            'type': 'potential_secret',
                            'severity': 'CRITICAL',
                            'description': f'Potential secret in ENV: {env.split("=")[0]}',
                            'remediation': 'Use secrets management instead of ENV'
                        })
            
            return issues
        
        def scan_for_secrets(self, image):
            '''Scan image layers for secrets'''
            
            secrets_found = []
            
            # Common secret patterns
            patterns = {
                'aws_key': r'AKIA[0-9A-Z]{16}',
                'github_token': r'ghp_[a-zA-Z0-9]{36}',
                'private_key': r'-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----',
                'api_key': r'api[_-]?key[_-]?[=:]\s*["\']?[a-zA-Z0-9]{32,}',
            }
            
            # Export image and scan
            # This is simplified - real implementation would extract layers
            
            return secrets_found
    """, language="python")
    
    # Dockerfile Security Best Practices
    st.markdown("### 📝 **Secure Dockerfile**")
    
    st.code("""
    # Secure Dockerfile Example
    
    # Use specific version, not latest
    FROM node:16.14.0-alpine AS builder
    
    # Create non-root user
    RUN addgroup -g 1001 -S nodejs && \\
        adduser -S nodejs -u 1001
    
    # Set working directory
    WORKDIR /app
    
    # Copy package files
    COPY package*.json ./
    
    # Install dependencies as root (needed for some packages)
    RUN npm ci --only=production && \\
        npm cache clean --force
    
    # Copy application files
    COPY --chown=nodejs:nodejs . .
    
    # Switch to non-root user
    USER nodejs
    
    # Don't expose unnecessary ports
    EXPOSE 3000
    
    # Health check
    HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
        CMD node healthcheck.js
    
    # Security headers
    ENV NODE_ENV=production
    
    # Run with limited resources
    CMD ["node", "--max-old-space-size=256", "server.js"]
    
    # Multi-stage build to reduce attack surface
    FROM node:16.14.0-alpine
    
    RUN apk add --no-cache tini
    
    WORKDIR /app
    
    # Copy only necessary files from builder
    COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
    COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
    
    USER nodejs
    
    ENTRYPOINT ["/sbin/tini", "--"]
    CMD ["node", "dist/server.js"]
    """, language="dockerfile")

def kubernetes_security_lab():
    """Kubernetes Security"""
    
    st.markdown(create_lab_header("Kubernetes Security Lab", "🎯", "linear-gradient(90deg, #00C9FF 0%, #92FE9D 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Kubernetes Security Theory**", expanded=True):
        st.markdown("""
        ### 🎯 **Understanding Kubernetes Security**
        
        Kubernetes (K8s) is the de-facto container orchestration platform, but its complexity creates numerous 
        security challenges. The "4C's of Cloud Native Security" - Cloud, Cluster, Container, and Code.
        
        **K8s Architecture Security Layers:**
        - ☁️ **Cloud/Infrastructure** - IaaS security
        - 🎯 **Cluster** - K8s control plane & nodes
        - 📦 **Container** - Image & runtime security
        - 💻 **Code** - Application security
        
        **Key Security Components:**
        
        1. **RBAC (Role-Based Access Control)**
           - Controls who can do what in cluster
           - Roles, ClusterRoles, Bindings
           - Principle of least privilege
           - Common mistake: Overly permissive roles
        
        2. **Network Policies**
           - Microsegmentation at pod level
           - Default: All traffic allowed
           - Ingress/Egress rules
           - Zero-trust networking
        
        3. **Pod Security**
           - Pod Security Standards (Restricted, Baseline, Privileged)
           - Security contexts (runAsNonRoot, readOnlyRootFilesystem)
           - Capabilities dropping
           - Resource limits
        
        4. **Secrets Management**
           - Base64 encoded (NOT encrypted by default!)
           - etcd encryption at rest
           - External secret managers
           - Sealed Secrets, SOPS
        
        **Common K8s Vulnerabilities:**
        - 🔓 **Exposed Dashboard** - Unauthenticated access
        - 🔑 **Overly Permissive RBAC** - Cluster-admin everywhere
        - 🌐 **No Network Policies** - Lateral movement
        - 📦 **Privileged Pods** - Container escape risk
        - 🔐 **Plain Text Secrets** - Credential exposure
        - 🎯 **Exposed kubelet** - Node compromise
        
        **Attack Scenarios:**
        - Container escape → Node access → Cluster takeover
        - Stolen service account → API access → Data theft
        - Supply chain → Malicious image → Backdoor
        - Misconfigured RBAC → Privilege escalation
        
        **Best Practices:**
        - Enable audit logging
        - Use admission controllers (OPA, Polaris)
        - Implement network policies
        - Regular CIS benchmark scans
        - Service mesh for mTLS
        - Runtime security (Falco)
        """)
    
    # K8s Security Components
    st.markdown("### 🛡️ **Kubernetes Security Components**")
    
    component = st.selectbox("Component:", ["RBAC", "Network Policies", "Pod Security", "Secrets Management", "Admission Controllers"])
    
    if component == "RBAC":
        st.markdown("#### **Role-Based Access Control**")
        
        st.code("""
        # RBAC Configuration
        
        apiVersion: rbac.authorization.k8s.io/v1
        kind: Role
        metadata:
          namespace: production
          name: pod-reader
        rules:
        - apiGroups: [""]
          resources: ["pods"]
          verbs: ["get", "watch", "list"]
        
        ---
        apiVersion: rbac.authorization.k8s.io/v1
        kind: RoleBinding
        metadata:
          name: read-pods
          namespace: production
        subjects:
        - kind: User
          name: developer
          apiGroup: rbac.authorization.k8s.io
        roleRef:
          kind: Role
          name: pod-reader
          apiGroup: rbac.authorization.k8s.io
        
        ---
        # Cluster-wide role for security scanning
        apiVersion: rbac.authorization.k8s.io/v1
        kind: ClusterRole
        metadata:
          name: security-scanner
        rules:
        - apiGroups: [""]
          resources: ["pods", "services", "configmaps", "secrets"]
          verbs: ["get", "list"]
        - apiGroups: ["apps"]
          resources: ["deployments", "daemonsets", "statefulsets"]
          verbs: ["get", "list"]
        """, language="yaml")
    
    elif component == "Network Policies":
        st.markdown("#### **Network Policies**")
        
        st.code("""
        # Kubernetes Network Policy
        
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: web-netpolicy
          namespace: production
        spec:
          podSelector:
            matchLabels:
              app: web
          policyTypes:
          - Ingress
          - Egress
          ingress:
          - from:
            - namespaceSelector:
                matchLabels:
                  name: production
            - podSelector:
                matchLabels:
                  app: frontend
            ports:
            - protocol: TCP
              port: 8080
          egress:
          - to:
            - podSelector:
                matchLabels:
                  app: database
            ports:
            - protocol: TCP
              port: 5432
          - to:
            - namespaceSelector:
                matchLabels:
                  name: kube-system
              podSelector:
                matchLabels:
                  k8s-app: kube-dns
            ports:
            - protocol: UDP
              port: 53
        
        ---
        # Default deny all traffic
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: default-deny-all
          namespace: production
        spec:
          podSelector: {}
          policyTypes:
          - Ingress
          - Egress
        """, language="yaml")
    
    elif component == "Pod Security":
        st.markdown("#### **Pod Security Standards**")
        
        st.code("""
        # Secure Pod Specification
        
        apiVersion: v1
        kind: Pod
        metadata:
          name: secure-pod
          namespace: production
        spec:
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            fsGroup: 2000
            seccompProfile:
              type: RuntimeDefault
          
          containers:
          - name: app
            image: myapp:1.0.0
            
            securityContext:
              allowPrivilegeEscalation: false
              readOnlyRootFilesystem: true
              runAsNonRoot: true
              runAsUser: 1000
              capabilities:
                drop:
                - ALL
                add:
                - NET_BIND_SERVICE
            
            resources:
              limits:
                memory: "256Mi"
                cpu: "500m"
              requests:
                memory: "128Mi"
                cpu: "250m"
            
            volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: cache
              mountPath: /app/cache
            
            livenessProbe:
              httpGet:
                path: /health
                port: 8080
              initialDelaySeconds: 30
              periodSeconds: 10
            
            readinessProbe:
              httpGet:
                path: /ready
                port: 8080
              initialDelaySeconds: 5
              periodSeconds: 5
          
          volumes:
          - name: tmp
            emptyDir: {}
          - name: cache
            emptyDir: {}
        
        ---
        # Pod Security Policy (deprecated, use Pod Security Standards)
        apiVersion: policy/v1beta1
        kind: PodSecurityPolicy
        metadata:
          name: restricted
        spec:
          privileged: false
          allowPrivilegeEscalation: false
          requiredDropCapabilities:
          - ALL
          volumes:
          - 'configMap'
          - 'emptyDir'
          - 'projected'
          - 'secret'
          - 'downwardAPI'
          - 'persistentVolumeClaim'
          hostNetwork: false
          hostIPC: false
          hostPID: false
          runAsUser:
            rule: 'MustRunAsNonRoot'
          seLinux:
            rule: 'RunAsAny'
          supplementalGroups:
            rule: 'RunAsAny'
          fsGroup:
            rule: 'RunAsAny'
        """, language="yaml")
    
    # K8s Security Scanner
    st.markdown("### 🔍 **Kubernetes Security Scanner**")
    
    st.code("""
    from kubernetes import client, config
    
    class K8sSecurityScanner:
        def __init__(self):
            config.load_incluster_config()  # Or load_kube_config() for local
            self.v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
            
        def scan_cluster(self):
            '''Comprehensive security scan of K8s cluster'''
            
            findings = {
                'critical': [],
                'high': [],
                'medium': [],
                'low': []
            }
            
            # Scan pods
            findings = self.scan_pods(findings)
            
            # Scan services
            findings = self.scan_services(findings)
            
            # Scan RBAC
            findings = self.scan_rbac(findings)
            
            # Scan secrets
            findings = self.scan_secrets(findings)
            
            return findings
        
        def scan_pods(self, findings):
            '''Scan pods for security issues'''
            
            pods = self.v1.list_pod_for_all_namespaces()
            
            for pod in pods.items:
                # Check if running as root
                for container in pod.spec.containers:
                    if not container.security_context:
                        findings['high'].append({
                            'type': 'missing_security_context',
                            'resource': f"pod/{pod.metadata.name}",
                            'namespace': pod.metadata.namespace,
                            'container': container.name
                        })
                    elif not container.security_context.run_as_non_root:
                        findings['critical'].append({
                            'type': 'running_as_root',
                            'resource': f"pod/{pod.metadata.name}",
                            'namespace': pod.metadata.namespace,
                            'container': container.name
                        })
                    
                    # Check for privileged containers
                    if container.security_context and container.security_context.privileged:
                        findings['critical'].append({
                            'type': 'privileged_container',
                            'resource': f"pod/{pod.metadata.name}",
                            'namespace': pod.metadata.namespace,
                            'container': container.name
                        })
                    
                    # Check for latest tag
                    if ':latest' in container.image or ':' not in container.image:
                        findings['medium'].append({
                            'type': 'latest_tag',
                            'resource': f"pod/{pod.metadata.name}",
                            'namespace': pod.metadata.namespace,
                            'container': container.name,
                            'image': container.image
                        })
            
            return findings
    """, language="python")

def serverless_security_lab():
    """Serverless Security"""
    
    st.markdown(create_lab_header("Serverless Security Lab", "⚡", "linear-gradient(90deg, #FC466B 0%, #3F5EFB 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Serverless Security Theory**", expanded=True):
        st.markdown("""
        ### ⚡ **Understanding Serverless Security**
        
        Serverless computing eliminates infrastructure management but introduces unique security challenges. 
        Functions execute in ephemeral containers with no persistent state, changing the security paradigm.
        
        **Serverless Architecture Benefits:**
        - 🚀 **No Infrastructure** - Provider manages servers
        - 💰 **Cost Efficient** - Pay per execution
        - 📈 **Auto-scaling** - Handles load automatically
        - 🔧 **Less Maintenance** - No patching servers
        
        **Security Challenges:**
        
        1. **Expanded Attack Surface**
           - Each function is an entry point
           - Event-driven triggers (S3, API, Queue)
           - Third-party integrations
           - Increased complexity
        
        2. **Traditional Security Gaps**
           - No persistent security agents
           - Limited runtime protection
           - Stateless execution
           - Short-lived containers (cold starts)
        
        3. **New Attack Vectors**
           - Event injection attacks
           - Function flow manipulation
           - Denial of Wallet (cost attacks)
           - Privilege escalation via roles
        
        4. **Monitoring Challenges**
           - Distributed tracing complexity
           - Limited visibility
           - Ephemeral logs
           - Multiple event sources
        
        **Common Vulnerabilities:**
        - 🔓 **Over-privileged Functions** - Excessive IAM permissions
        - 💉 **Injection Attacks** - Event data injection
        - 🔑 **Hardcoded Secrets** - API keys in code
        - 📊 **Data Exposure** - Logging sensitive data
        - ⏱️ **Timeout Exploitation** - Resource exhaustion
        - 🎯 **Function Event-Data Injection** - Malicious payloads
        
        **Attack Scenarios:**
        - S3 upload → Lambda trigger → Code execution
        - API Gateway → Lambda → Privilege escalation
        - SQS poisoning → Lambda → Data exfiltration
        - Cost attacks via infinite loops
        
        **Best Practices:**
        - Principle of least privilege IAM
        - Input validation for all events
        - Secrets management (not env vars!)
        - Function isolation & segmentation
        - Timeout and memory limits
        - Enable tracing (X-Ray, Application Insights)
        - Regular vulnerability scanning
        - Code signing & integrity
        """)
    
    # Serverless Platforms
    platform = st.selectbox("Platform:", ["AWS Lambda", "Azure Functions", "Google Cloud Functions"])
    
    if platform == "AWS Lambda":
        st.markdown("### 🔶 **AWS Lambda Security**")
        
        st.code("""
        import boto3
        import json
        
        class LambdaSecurityManager:
            def __init__(self):
                self.lambda_client = boto3.client('lambda')
                self.iam = boto3.client('iam')
                
            def secure_lambda_function(self, function_name):
                '''Apply security best practices to Lambda function'''
                
                # Get function configuration
                function = self.lambda_client.get_function(FunctionName=function_name)
                
                security_updates = {}
                
                # 1. Enable encryption at rest
                if not function['Configuration'].get('KMSKeyArn'):
                    kms_key = self.create_kms_key(function_name)
                    security_updates['KMSKeyArn'] = kms_key
                
                # 2. Set environment variable encryption
                environment = function['Configuration'].get('Environment', {})
                if environment and not environment.get('Variables', {}).get('ENCRYPTED'):
                    # Encrypt sensitive environment variables
                    security_updates['Environment'] = {
                        'Variables': self.encrypt_env_vars(environment.get('Variables', {}))
                    }
                
                # 3. Configure VPC for network isolation
                if not function['Configuration'].get('VpcConfig'):
                    vpc_config = self.get_secure_vpc_config()
                    security_updates['VpcConfig'] = vpc_config
                
                # 4. Set appropriate timeout and memory
                security_updates['Timeout'] = 30  # 30 seconds max
                security_updates['MemorySize'] = 256  # Reasonable memory limit
                
                # 5. Enable tracing
                security_updates['TracingConfig'] = {'Mode': 'Active'}
                
                # Apply updates
                if security_updates:
                    self.lambda_client.update_function_configuration(
                        FunctionName=function_name,
                        **security_updates
                    )
                
                # 6. Update IAM role with least privilege
                self.update_lambda_role(function['Configuration']['Role'])
                
                # 7. Set resource-based policy
                self.set_resource_policy(function_name)
                
                return True
            
            def update_lambda_role(self, role_arn):
                '''Apply least privilege to Lambda execution role'''
                
                role_name = role_arn.split('/')[-1]
                
                # Least privilege policy
                policy_document = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "logs:CreateLogGroup",
                                "logs:CreateLogStream",
                                "logs:PutLogEvents"
                            ],
                            "Resource": f"arn:aws:logs:*:*:log-group:/aws/lambda/*"
                        },
                        {
                            "Effect": "Allow",
                            "Action": [
                                "xray:PutTraceSegments",
                                "xray:PutTelemetryRecords"
                            ],
                            "Resource": "*"
                        },
                        {
                            "Effect": "Deny",
                            "Action": [
                                "iam:*",
                                "ec2:TerminateInstances",
                                "s3:DeleteBucket"
                            ],
                            "Resource": "*"
                        }
                    ]
                }
                
                # Update or create policy
                try:
                    self.iam.put_role_policy(
                        RoleName=role_name,
                        PolicyName='LambdaLeastPrivilege',
                        PolicyDocument=json.dumps(policy_document)
                    )
                except Exception as e:
                    print(f"Error updating role: {e}")
            
            def scan_lambda_vulnerabilities(self, function_name):
                '''Scan Lambda function for security issues'''
                
                vulnerabilities = []
                
                function = self.lambda_client.get_function(FunctionName=function_name)
                config = function['Configuration']
                
                # Check for security issues
                if not config.get('KMSKeyArn'):
                    vulnerabilities.append({
                        'type': 'no_encryption',
                        'severity': 'HIGH',
                        'description': 'Function not encrypted at rest'
                    })
                
                if config.get('Timeout', 0) > 300:
                    vulnerabilities.append({
                        'type': 'excessive_timeout',
                        'severity': 'MEDIUM',
                        'description': 'Timeout > 5 minutes increases attack window'
                    })
                
                # Check environment variables for secrets
                env_vars = config.get('Environment', {}).get('Variables', {})
                for key, value in env_vars.items():
                    if any(secret in key.upper() for secret in ['PASSWORD', 'SECRET', 'KEY', 'TOKEN']):
                        vulnerabilities.append({
                            'type': 'hardcoded_secret',
                            'severity': 'CRITICAL',
                            'description': f'Potential secret in environment: {key}'
                        })
                
                # Check IAM role permissions
                role_arn = config['Role']
                role_vulns = self.check_role_permissions(role_arn)
                vulnerabilities.extend(role_vulns)
                
                return vulnerabilities
        """, language="python")
    
    # Serverless Security Best Practices
    st.markdown("### ✅ **Serverless Security Best Practices**")
    
    practices = [
        "Use least privilege IAM roles",
        "Encrypt environment variables",
        "Enable VPC for network isolation",
        "Implement input validation",
        "Use AWS Secrets Manager for secrets",
        "Enable X-Ray tracing",
        "Set appropriate timeouts",
        "Implement rate limiting",
        "Use Lambda layers for dependencies",
        "Regular vulnerability scanning"
    ]
    
    for practice in practices:
        st.success(f"✓ {practice}")

def cspm_lab():
    """Cloud Security Posture Management"""
    
    st.markdown(create_lab_header("CSPM Lab", "🔍", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **CSPM Theory**", expanded=True):
        st.markdown("""
        ### 🔍 **Understanding Cloud Security Posture Management (CSPM)**
        
        CSPM continuously monitors cloud infrastructures for gaps in security policy enforcement, providing 
        visibility, compliance monitoring, and automated remediation across multi-cloud environments.
        
        **Why CSPM is Critical:**
        - ☁️ **Cloud Complexity** - Hundreds of services, thousands of configs
        - 🔄 **Constant Changes** - DevOps speed = configuration drift
        - 👥 **Human Error** - 95% of cloud breaches from misconfig
        - 📊 **Compliance** - Multiple standards (PCI, HIPAA, SOC2)
        
        **Core CSPM Capabilities:**
        
        1. **Misconfiguration Detection**
           - Public S3 buckets
           - Open security groups
           - Unencrypted databases
           - Excessive IAM permissions
           - Default passwords
        
        2. **Compliance Assessment**
           - CIS Benchmarks
           - PCI-DSS requirements
           - HIPAA controls
           - GDPR compliance
           - Custom policies
        
        3. **Risk Visualization**
           - Security score/rating
           - Risk heat maps
           - Trend analysis
           - Priority scoring
        
        4. **Automated Remediation**
           - Auto-fix common issues
           - Workflow integration
           - Rollback capabilities
           - Change tracking
        
        **Common Cloud Misconfigurations:**
        - 🔓 **Storage** - 73% have exposed S3/Blob/GCS
        - 🌐 **Network** - 65% have overly permissive rules
        - 🔑 **IAM** - 58% have excessive permissions
        - 💾 **Encryption** - 45% missing encryption
        - 📝 **Logging** - 40% inadequate audit logs
        
        **CSPM vs Other Tools:**
        
        | Tool | Focus | When to Use |
        |------|-------|-------------|
        | CSPM | Configuration | Posture management |
        | CWPP | Workload | Runtime protection |
        | CASB | SaaS | App security |
        | CIEM | Identity | Entitlement management |
        
        **Implementation Strategy:**
        1. Discovery - Inventory all cloud assets
        2. Assessment - Evaluate against policies
        3. Prioritization - Risk-based ranking
        4. Remediation - Fix critical issues
        5. Prevention - Shift-left with IaC scanning
        
        **Best Practices:**
        - Enable for all cloud accounts
        - Integrate with SIEM/SOAR
        - Custom policies for business
        - Regular compliance reports
        - Automated remediation workflows
        """)
    
    # CSPM Implementation
    st.markdown("### 🛡️ **Cloud Security Posture Management**")
    
    st.code("""
    import boto3
    import json
    from datetime import datetime
    
    class CloudSecurityPostureManager:
        def __init__(self):
            self.services = {
                'ec2': boto3.client('ec2'),
                's3': boto3.client('s3'),
                'iam': boto3.client('iam'),
                'rds': boto3.client('rds'),
                'config': boto3.client('config')
            }
            self.compliance_standards = ['CIS', 'PCI-DSS', 'HIPAA', 'SOC2']
            
        def assess_security_posture(self):
            '''Comprehensive cloud security assessment'''
            
            assessment = {
                'timestamp': datetime.now().isoformat(),
                'score': 0,
                'max_score': 0,
                'findings': [],
                'compliance': {}
            }
            
            # Run security checks
            checks = [
                self.check_iam_security,
                self.check_network_security,
                self.check_data_security,
                self.check_logging_monitoring,
                self.check_incident_response
            ]
            
            for check in checks:
                result = check()
                assessment['findings'].extend(result['findings'])
                assessment['score'] += result['score']
                assessment['max_score'] += result['max_score']
            
            # Calculate overall score
            assessment['percentage'] = (assessment['score'] / assessment['max_score']) * 100
            
            # Check compliance
            for standard in self.compliance_standards:
                assessment['compliance'][standard] = self.check_compliance(standard, assessment['findings'])
            
            return assessment
        
        def check_iam_security(self):
            '''Check IAM security configurations'''
            
            findings = []
            score = 0
            max_score = 100
            
            # Check for root account usage
            try:
                account_summary = self.services['iam'].get_account_summary()
                
                # Check MFA on root
                if account_summary['SummaryMap'].get('AccountMFAEnabled', 0) == 0:
                    findings.append({
                        'service': 'IAM',
                        'check': 'Root MFA',
                        'status': 'FAIL',
                        'severity': 'CRITICAL',
                        'description': 'MFA not enabled on root account'
                    })
                else:
                    score += 20
                
                # Check password policy
                try:
                    password_policy = self.services['iam'].get_account_password_policy()
                    policy = password_policy['PasswordPolicy']
                    
                    if policy.get('MinimumPasswordLength', 0) < 14:
                        findings.append({
                            'service': 'IAM',
                            'check': 'Password Policy',
                            'status': 'FAIL',
                            'severity': 'HIGH',
                            'description': 'Password minimum length < 14'
                        })
                    else:
                        score += 10
                        
                    if not policy.get('RequireUppercaseCharacters'):
                        findings.append({
                            'service': 'IAM',
                            'check': 'Password Complexity',
                            'status': 'FAIL',
                            'severity': 'MEDIUM',
                            'description': 'Password policy does not require uppercase'
                        })
                    else:
                        score += 10
                        
                except:
                    findings.append({
                        'service': 'IAM',
                        'check': 'Password Policy',
                        'status': 'FAIL',
                        'severity': 'HIGH',
                        'description': 'No password policy configured'
                    })
                
                # Check for unused credentials
                users = self.services['iam'].list_users()
                for user in users['Users']:
                    # Check access key age
                    access_keys = self.services['iam'].list_access_keys(UserName=user['UserName'])
                    for key in access_keys['AccessKeyMetadata']:
                        age = (datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']).days
                        if age > 90:
                            findings.append({
                                'service': 'IAM',
                                'check': 'Access Key Rotation',
                                'status': 'FAIL',
                                'severity': 'MEDIUM',
                                'description': f'Access key for {user["UserName"]} is {age} days old'
                            })
                        else:
                            score += 2
                
            except Exception as e:
                findings.append({
                    'service': 'IAM',
                    'check': 'General',
                    'status': 'ERROR',
                    'description': str(e)
                })
            
            return {
                'findings': findings,
                'score': score,
                'max_score': max_score
            }
        
        def generate_remediation_plan(self, findings):
            '''Generate automated remediation plan'''
            
            remediation_plan = {
                'automated': [],
                'manual': [],
                'scripts': {}
            }
            
            for finding in findings:
                if finding['severity'] in ['CRITICAL', 'HIGH']:
                    # Generate remediation based on finding type
                    if 'MFA' in finding['description']:
                        remediation_plan['manual'].append({
                            'finding': finding,
                            'action': 'Enable MFA on root account',
                            'priority': 1
                        })
                    
                    elif 'public' in finding['description'].lower():
                        remediation_plan['automated'].append({
                            'finding': finding,
                            'action': 'Block public access',
                            'script': 'remediate_public_access',
                            'priority': 1
                        })
                        
                        # Add remediation script
                        remediation_plan['scripts']['remediate_public_access'] = '''
                        # Block S3 public access
                        aws s3api put-public-access-block \\
                            --bucket BUCKET_NAME \\
                            --public-access-block-configuration \\
                            "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                        '''
            
            return remediation_plan
    """, language="python")
    
    # CSPM Dashboard
    st.markdown("### 📊 **Security Posture Dashboard**")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Security Score", "78/100", "+5")
    
    with col2:
        st.metric("Critical Findings", "3", "-2")
    
    with col3:
        st.metric("Compliance", "85%", "+3%")
    
    with col4:
        st.metric("Resources Scanned", "1,247")

def cwpp_lab():
    """Cloud Workload Protection Platform"""
    
    st.markdown(create_lab_header("CWPP Lab", "🛡️", "linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **CWPP Theory**", expanded=True):
        st.markdown("""
        ### 🛡️ **Understanding Cloud Workload Protection Platform (CWPP)**
        
        CWPP provides comprehensive security for workloads across physical servers, VMs, containers, and 
        serverless functions, protecting against threats throughout the application lifecycle.
        
        **Evolution of Workload Protection:**
        - 🖥️ **Traditional** - Endpoint protection for servers
        - ☁️ **Cloud-Native** - Container & serverless security
        - 🔄 **Hybrid** - Consistent protection across environments
        - 🤖 **Modern** - ML-based behavioral analysis
        
        **CWPP Core Components:**
        
        1. **Workload Hardening**
           - System integrity monitoring
           - Configuration management
           - Vulnerability management
           - Patch management
        
        2. **Runtime Protection**
           - Anti-malware/Anti-exploit
           - Application control
           - Behavioral monitoring
           - Memory protection
        
        3. **Network Security**
           - Microsegmentation
           - East-West traffic inspection
           - Connection control
           - Encrypted traffic analysis
        
        4. **Container Security**
           - Image scanning
           - Runtime defense
           - Admission control
           - Drift prevention
        
        **Workload Types & Risks:**
        
        | Workload | Key Risks | Protection Focus |
        |----------|-----------|------------------|
        | VMs | Malware, patches | AV, hardening |
        | Containers | Escape, images | Runtime, scanning |
        | Serverless | Event injection | Input validation |
        | Kubernetes | RBAC, network | Policy, segmentation |
        
        **Attack Detection Methods:**
        - 🔍 **Signature-based** - Known malware patterns
        - 🧠 **Behavioral** - Anomaly detection
        - 🎯 **Heuristic** - Suspicious activities
        - 🔬 **Machine Learning** - Advanced threats
        
        **CWPP vs CSPM:**
        - **CSPM** = Configuration security (preventive)
        - **CWPP** = Runtime security (detective/responsive)
        - **Together** = Complete cloud security
        
        **Implementation Challenges:**
        - Performance impact on workloads
        - Container ephemeral nature
        - Serverless visibility gaps
        - Multi-cloud consistency
        
        **Best Practices:**
        - Deploy agents strategically
        - Enable auto-scaling compatibility
        - Integrate with CI/CD pipeline
        - Centralized policy management
        - Regular security assessments
        """)
    
    st.markdown("### 🔒 **Cloud Workload Protection**")
    
    st.code("""
    class CloudWorkloadProtection:
        def __init__(self):
            self.workloads = []
            self.policies = []
            
        def protect_workload(self, workload_id, workload_type):
            '''Apply protection to cloud workload'''
            
            protection_config = {
                'workload_id': workload_id,
                'type': workload_type,
                'protections': []
            }
            
            # Runtime protection
            if workload_type == 'container':
                protection_config['protections'].extend([
                    'runtime_scanning',
                    'behavioral_monitoring',
                    'network_segmentation',
                    'secrets_scanning'
                ])
            
            elif workload_type == 'serverless':
                protection_config['protections'].extend([
                    'function_monitoring',
                    'api_protection',
                    'data_flow_analysis'
                ])
            
            elif workload_type == 'vm':
                protection_config['protections'].extend([
                    'host_intrusion_prevention',
                    'file_integrity_monitoring',
                    'anti_malware'
                ])
            
            return protection_config
        
        def runtime_protection(self, container_id):
            '''Runtime protection for containers'''
            
            # Monitor system calls
            syscall_monitor = self.monitor_syscalls(container_id)
            
            # Detect anomalies
            if syscall_monitor['anomaly_detected']:
                self.respond_to_threat(container_id, syscall_monitor['threat_type'])
            
            # File integrity monitoring
            file_changes = self.monitor_file_integrity(container_id)
            
            # Network monitoring
            network_activity = self.monitor_network(container_id)
            
            return {
                'container_id': container_id,
                'syscalls': syscall_monitor,
                'file_integrity': file_changes,
                'network': network_activity
            }
    """, language="python")

def api_gateway_lab():
    """API Gateway Security"""
    
    st.markdown(create_lab_header("API Gateway Lab", "🌐", "linear-gradient(90deg, #00C9FF 0%, #92FE9D 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **API Gateway Security Theory**", expanded=True):
        st.markdown("""
        ### 🌐 **Understanding API Gateway Security**
        
        API Gateways are the front door to microservices, handling authentication, authorization, rate limiting, 
        and threat protection. They're critical security enforcement points in modern architectures.
        
        **Why API Gateway Security Matters:**
        - 🎯 **Single Entry Point** - All API traffic flows through
        - 💰 **High Value Target** - Access to backend services
        - 📈 **API Growth** - 83% of web traffic is API
        - 🔓 **Common Vulnerabilities** - OWASP API Top 10
        
        **API Security Threats:**
        
        1. **Broken Authentication**
           - Weak API keys
           - No token expiration
           - Predictable tokens
           - Missing MFA
        
        2. **Excessive Data Exposure**
           - Returning full objects
           - Sensitive data in responses
           - No field filtering
        
        3. **Rate Limiting Issues**
           - No rate limits
           - DDoS vulnerability
           - Resource exhaustion
           - Cost attacks
        
        4. **Injection Attacks**
           - SQL injection via parameters
           - NoSQL injection
           - Command injection
           - XXE attacks
        
        **OWASP API Security Top 10 (2023):**
        1. Broken Object Level Authorization (BOLA)
        2. Broken Authentication
        3. Broken Object Property Level Authorization
        4. Unrestricted Resource Consumption
        5. Broken Function Level Authorization
        6. Unrestricted Access to Sensitive Business Flows
        7. Server Side Request Forgery (SSRF)
        8. Security Misconfiguration
        9. Improper Inventory Management
        10. Unsafe Consumption of APIs
        
        **Gateway Security Features:**
        - 🔐 **Authentication** - OAuth2, JWT, API keys
        - 👮 **Authorization** - RBAC, ABAC, scopes
        - 🚦 **Rate Limiting** - Throttling, quotas
        - 🛡️ **WAF Integration** - Attack protection
        - 📊 **Analytics** - Usage patterns, anomalies
        - 🔄 **Load Balancing** - Distribute traffic
        
        **Implementation Patterns:**
        
        | Pattern | Use Case | Security Benefit |
        |---------|----------|------------------|
        | Edge Gateway | Public APIs | Perimeter security |
        | BFF | Mobile/Web | Client-specific security |
        | Service Mesh | Microservices | Zero-trust networking |
        | API Proxy | Legacy systems | Security wrapper |
        
        **Best Practices:**
        - Always use HTTPS/TLS 1.3
        - Implement proper authentication
        - Rate limit all endpoints
        - Validate all inputs
        - Log and monitor everything
        - Version your APIs
        - Use API specifications (OpenAPI)
        """)
    
    st.markdown("### 🔐 **API Gateway Security Configuration**")
    
    st.code("""
    # API Gateway Security Configuration
    
    class APIGatewaySecurity:
        def __init__(self):
            self.rate_limits = {}
            self.api_keys = {}
            self.policies = []
            
        def configure_security(self, api_name):
            '''Configure comprehensive API security'''
            
            config = {
                'api_name': api_name,
                'authentication': 'oauth2',
                'authorization': 'rbac',
                'rate_limiting': {
                    'requests_per_second': 100,
                    'burst_limit': 200,
                    'per_api_key': True
                },
                'waf_rules': [
                    'sql_injection_protection',
                    'xss_protection',
                    'size_restrictions',
                    'ip_whitelist'
                ],
                'logging': {
                    'access_logs': True,
                    'execution_logs': True,
                    'data_trace': False  # PII protection
                },
                'cors': {
                    'allowed_origins': ['https://trusted-domain.com'],
                    'allowed_methods': ['GET', 'POST'],
                    'allowed_headers': ['Content-Type', 'Authorization'],
                    'max_age': 3600
                },
                'request_validation': {
                    'validate_body': True,
                    'validate_parameters': True,
                    'validate_headers': True
                },
                'response_transformation': {
                    'remove_sensitive_headers': True,
                    'add_security_headers': {
                        'X-Content-Type-Options': 'nosniff',
                        'X-Frame-Options': 'DENY',
                        'Content-Security-Policy': "default-src 'self'"
                    }
                }
            }
            
            return config
        
        def implement_rate_limiting(self, api_key, endpoint):
            '''Implement rate limiting with token bucket'''
            
            import time
            
            if api_key not in self.rate_limits:
                self.rate_limits[api_key] = {
                    'tokens': 100,
                    'last_refill': time.time(),
                    'max_tokens': 100,
                    'refill_rate': 10  # tokens per second
                }
            
            bucket = self.rate_limits[api_key]
            current_time = time.time()
            
            # Refill tokens
            time_passed = current_time - bucket['last_refill']
            tokens_to_add = time_passed * bucket['refill_rate']
            bucket['tokens'] = min(bucket['max_tokens'], bucket['tokens'] + tokens_to_add)
            bucket['last_refill'] = current_time
            
            # Check if request allowed
            if bucket['tokens'] >= 1:
                bucket['tokens'] -= 1
                return True, bucket['tokens']
            else:
                return False, 0
    """, language="python")

def data_security_lab():
    """Cloud Data Security"""
    
    st.markdown(create_lab_header("Data Security Lab", "💾", "linear-gradient(90deg, #FC466B 0%, #3F5EFB 100%)"), unsafe_allow_html=True)
    
    # Theory Section
    with st.expander("📖 **Data Security Theory**", expanded=True):
        st.markdown("""
        ### 💾 **Understanding Cloud Data Security**
        
        Data is the crown jewel of any organization. In the cloud, data security involves protecting information 
        throughout its lifecycle - at rest, in transit, and in use - across multiple services and regions.
        
        **Data Security Challenges in Cloud:**
        - 🌍 **Data Residency** - Compliance with local laws
        - 🔄 **Data Mobility** - Moving between services/regions
        - 👥 **Shared Responsibility** - Provider vs customer
        - 🔑 **Key Management** - Encryption key control
        - 📊 **Data Classification** - Identifying sensitive data
        
        **Data States & Protection:**
        
        1. **Data at Rest**
           - Storage encryption (AES-256)
           - Database encryption (TDE)
           - Backup encryption
           - Key rotation
           - Hardware Security Modules (HSM)
        
        2. **Data in Transit**
           - TLS/SSL encryption
           - VPN tunnels
           - Private connectivity (Direct Connect, ExpressRoute)
           - Certificate management
           - mTLS for service-to-service
        
        3. **Data in Use**
           - Homomorphic encryption
           - Secure enclaves (SGX, Nitro)
           - Confidential computing
           - Tokenization
           - Format-preserving encryption
        
        **Common Data Breaches:**
        - 🔓 **Misconfigured Storage** - Public S3 buckets
        - 💾 **Unencrypted Databases** - RDS, MongoDB exposed
        - 📧 **Data Leakage** - Via logs, emails, APIs
        - 🔑 **Stolen Credentials** - Access to data stores
        - 💼 **Insider Threats** - Authorized user abuse
        
        **Data Loss Prevention (DLP):**
        
        | Component | Function | Example |
        |-----------|----------|---------|
        | Discovery | Find sensitive data | Credit cards in S3 |
        | Classification | Label data types | PII, PHI, PCI |
        | Monitoring | Track data movement | Egress to internet |
        | Prevention | Block violations | Stop data export |
        | Remediation | Fix issues | Encrypt, redact |
        
        **Encryption Key Management:**
        - **Customer Managed (CMK)** - You control keys
        - **Provider Managed** - Cloud provider controls
        - **Bring Your Own Key (BYOK)** - Import external keys
        - **Hold Your Own Key (HYOK)** - Keys never leave premises
        
        **Compliance Requirements:**
        - **GDPR** - EU data protection
        - **HIPAA** - Healthcare data (USA)
        - **PCI-DSS** - Payment card data
        - **SOC 2** - Service organization controls
        - **ISO 27001** - Information security
        
        **Best Practices:**
        - Encrypt everything by default
        - Implement data classification
        - Use separate encryption keys per data type
        - Enable audit logging for all data access
        - Regular key rotation (90 days)
        - Implement least privilege access
        - Use data masking for non-production
        - Regular compliance audits
        """)
    
    st.markdown("### 🔒 **Data Protection in Cloud**")
    
    protection_type = st.selectbox("Protection Type:", ["Encryption at Rest", "Encryption in Transit", "Data Loss Prevention", "Key Management"])
    
    if protection_type == "Encryption at Rest":
        st.code("""
        # Cloud Data Encryption at Rest
        
        import boto3
        from cryptography.fernet import Fernet
        
        class CloudDataEncryption:
            def __init__(self):
                self.kms = boto3.client('kms')
                self.s3 = boto3.client('s3')
                
            def encrypt_s3_bucket(self, bucket_name):
                '''Enable encryption for S3 bucket'''
                
                # Create KMS key for bucket
                key_response = self.kms.create_key(
                    Description=f'KMS key for {bucket_name}',
                    KeyUsage='ENCRYPT_DECRYPT',
                    Origin='AWS_KMS'
                )
                
                key_id = key_response['KeyMetadata']['KeyId']
                
                # Apply bucket encryption
                self.s3.put_bucket_encryption(
                    Bucket=bucket_name,
                    ServerSideEncryptionConfiguration={
                        'Rules': [{
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'aws:kms',
                                'KMSMasterKeyID': key_id
                            },
                            'BucketKeyEnabled': True
                        }]
                    }
                )
                
                # Enable versioning for additional protection
                self.s3.put_bucket_versioning(
                    Bucket=bucket_name,
                    VersioningConfiguration={'Status': 'Enabled'}
                )
                
                return key_id
            
            def encrypt_database(self, db_instance_id):
                '''Enable encryption for RDS database'''
                
                rds = boto3.client('rds')
                
                # Create encrypted snapshot
                snapshot_id = f"{db_instance_id}-encrypted-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                
                rds.create_db_snapshot(
                    DBSnapshotIdentifier=snapshot_id,
                    DBInstanceIdentifier=db_instance_id
                )
                
                # Wait for snapshot
                waiter = rds.get_waiter('db_snapshot_completed')
                waiter.wait(DBSnapshotIdentifier=snapshot_id)
                
                # Copy snapshot with encryption
                encrypted_snapshot_id = f"{snapshot_id}-encrypted"
                
                rds.copy_db_snapshot(
                    SourceDBSnapshotIdentifier=snapshot_id,
                    TargetDBSnapshotIdentifier=encrypted_snapshot_id,
                    KmsKeyId='alias/aws/rds'
                )
                
                # Restore from encrypted snapshot
                rds.restore_db_instance_from_db_snapshot(
                    DBInstanceIdentifier=f"{db_instance_id}-encrypted",
                    DBSnapshotIdentifier=encrypted_snapshot_id
                )
                
                return encrypted_snapshot_id
        """, language="python")

def compliance_lab():
    """Cloud Compliance Management"""
    
    st.markdown(create_lab_header("Compliance Lab", "📊", "linear-gradient(90deg, #f093fb 0%, #f5576c 100%)"), unsafe_allow_html=True)
    
    st.markdown("### 📋 **Compliance Standards**")
    
    standard = st.selectbox("Compliance Standard:", ["PCI-DSS", "HIPAA", "SOC 2", "GDPR", "ISO 27001"])
    
    if standard == "PCI-DSS":
        st.markdown("#### **PCI-DSS Compliance Checklist**")
        
        requirements = [
            "Build and maintain a secure network",
            "Protect cardholder data",
            "Maintain vulnerability management program",
            "Implement strong access control",
            "Regularly monitor and test networks",
            "Maintain information security policy"
        ]
        
        for req in requirements:
            st.checkbox(req, key=f"pci_{req}")
        
        st.code("""
        # PCI-DSS Compliance Scanner
        
        class PCIDSSComplianceChecker:
            def __init__(self):
                self.requirements = {
                    '1.1': 'Firewall configuration standards',
                    '2.1': 'Default passwords changed',
                    '3.1': 'Cardholder data retention policy',
                    '4.1': 'Strong cryptography for transmission',
                    '5.1': 'Anti-virus deployed',
                    '6.1': 'Security patches up to date',
                    '7.1': 'Access control by business need',
                    '8.1': 'Unique user IDs',
                    '9.1': 'Physical access restrictions',
                    '10.1': 'Audit trails implemented',
                    '11.1': 'Security testing procedures',
                    '12.1': 'Security policy established'
                }
                
            def check_compliance(self, environment):
                '''Check PCI-DSS compliance'''
                
                compliance_report = {
                    'compliant': True,
                    'score': 0,
                    'max_score': len(self.requirements),
                    'findings': []
                }
                
                # Check each requirement
                for req_id, description in self.requirements.items():
                    result = self.check_requirement(req_id, environment)
                    
                    if result['compliant']:
                        compliance_report['score'] += 1
                    else:
                        compliance_report['compliant'] = False
                        compliance_report['findings'].append({
                            'requirement': req_id,
                            'description': description,
                            'status': 'NON_COMPLIANT',
                            'details': result['details'],
                            'remediation': result['remediation']
                        })
                
                compliance_report['percentage'] = (
                    compliance_report['score'] / compliance_report['max_score']
                ) * 100
                
                return compliance_report
        """, language="python")

def devsecops_cloud_lab():
    """DevSecOps in Cloud"""
    
    st.markdown(create_lab_header("DevSecOps Cloud Lab", "🚀", "linear-gradient(90deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)"), unsafe_allow_html=True)
    
    st.markdown("### 🔧 **Cloud-Native DevSecOps Pipeline**")
    
    st.code("""
    # Cloud DevSecOps Pipeline
    
    version: '3'
    
    stages:
      - security_scan
      - build
      - test
      - deploy
      - monitor
    
    security_scan:
      stage: security_scan
      script:
        # SAST - Static Application Security Testing
        - semgrep --config=auto .
        
        # Secret scanning
        - trufflehog filesystem . --json
        
        # Dependency scanning
        - safety check --json
        - npm audit
        
        # IaC scanning
        - checkov -d . --framework terraform
        - tfsec .
        
        # Container scanning
        - trivy image ${IMAGE_NAME}:${CI_COMMIT_SHA}
        
    build:
      stage: build
      script:
        # Build with security flags
        - docker build \\
            --build-arg BUILDKIT_INLINE_CACHE=1 \\
            --label "security.scan=true" \\
            --label "commit.sha=${CI_COMMIT_SHA}" \\
            -t ${IMAGE_NAME}:${CI_COMMIT_SHA} .
        
        # Sign image
        - cosign sign ${IMAGE_NAME}:${CI_COMMIT_SHA}
        
        # Generate SBOM
        - syft ${IMAGE_NAME}:${CI_COMMIT_SHA} -o spdx-json > sbom.json
        
    test:
      stage: test
      script:
        # DAST - Dynamic Application Security Testing
        - |
          docker run --rm \\
            -v $(pwd):/zap/wrk/:rw \\
            owasp/zap2docker-stable zap-baseline.py \\
            -t https://${TEST_URL} \\
            -J zap-report.json
        
        # API Security Testing
        - newman run api-security-tests.json
        
    deploy:
      stage: deploy
      script:
        # Deploy to Kubernetes with security policies
        - |
          kubectl apply -f - <<EOF
          apiVersion: v1
          kind: Namespace
          metadata:
            name: production
            labels:
              pod-security.kubernetes.io/enforce: restricted
              pod-security.kubernetes.io/audit: restricted
              pod-security.kubernetes.io/warn: restricted
          EOF
        
        # Apply network policies
        - kubectl apply -f network-policies/
        
        # Deploy with OPA policies
        - opa test policies/
        - kubectl apply -f deployment.yaml
        
    monitor:
      stage: monitor
      script:
        # Runtime security monitoring
        - falco -r /etc/falco/falco_rules.yaml
        
        # Cloud security posture
        - prowler -g cis_level2
        
        # Vulnerability monitoring
        - grype ${IMAGE_NAME}:${CI_COMMIT_SHA}
    """, language="yaml")
    
    # DevSecOps Metrics
    st.markdown("### 📊 **DevSecOps Metrics**")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Vulnerabilities Found", "23", "-7")
        st.metric("Fixed in Dev", "95%", "+5%")
    
    with col2:
        st.metric("Mean Time to Remediate", "2.3 days", "-0.5")
        st.metric("Security Debt", "Low", "↓")
    
    with col3:
        st.metric("Scan Coverage", "98%", "+2%")
        st.metric("False Positives", "3%", "-1%")
    
    with col4:
        st.metric("Deployment Frequency", "12/day", "+3")
        st.metric("Security Gates Passed", "100%", "✅")

if __name__ == "__main__":
    run_lab()
