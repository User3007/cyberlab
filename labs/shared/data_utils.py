"""
Data processing utilities for the cybersecurity lab
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import random
from .constants import DEMO_DATA_CONFIG


def create_comparison_table(data: List[Dict[str, Any]],
                          columns: List[str] = None,
                          highlight_best: bool = True) -> pd.DataFrame:
    """Create formatted comparison table"""
    
    df = pd.DataFrame(data)
    
    if columns:
        df = df[columns]
    
    # Apply highlighting if requested
    if highlight_best:
        df = df.style.apply(_highlight_best_values, axis=0)
    
    return df


def _highlight_best_values(series):
    """Highlight best values in a series"""
    if series.dtype in ['int64', 'float64']:
        max_val = series.max()
        return ['background-color: #d4edda' if val == max_val else '' for val in series]
    return ['' for _ in series]


def format_metrics(metrics: Dict[str, float],
                  format_type: str = 'percentage',
                  decimal_places: int = 2) -> Dict[str, str]:
    """Format metrics for display"""
    
    formatted = {}
    
    for key, value in metrics.items():
        if format_type == 'percentage':
            formatted[key] = f"{value:.{decimal_places}%}"
        elif format_type == 'currency':
            formatted[key] = f"${value:,.{decimal_places}f}"
        elif format_type == 'number':
            formatted[key] = f"{value:,.{decimal_places}f}"
        elif format_type == 'bytes':
            formatted[key] = _format_bytes(value)
        else:
            formatted[key] = str(value)
    
    return formatted


def _format_bytes(bytes_value: float) -> str:
    """Format bytes into human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def generate_demo_data(data_type: str,
                      size: int = None,
                      **kwargs) -> pd.DataFrame:
    """Generate demo data for various scenarios"""
    
    if size is None:
        size = DEMO_DATA_CONFIG['sample_size']
    
    np.random.seed(DEMO_DATA_CONFIG['random_seed'])
    
    if data_type == 'network_traffic':
        return _generate_network_traffic_data(size, **kwargs)
    elif data_type == 'security_incidents':
        return _generate_security_incidents_data(size, **kwargs)
    elif data_type == 'performance_metrics':
        return _generate_performance_metrics_data(size, **kwargs)
    elif data_type == 'vulnerability_scan':
        return _generate_vulnerability_scan_data(size, **kwargs)
    elif data_type == 'user_activity':
        return _generate_user_activity_data(size, **kwargs)
    else:
        raise ValueError(f"Unknown data type: {data_type}")


def _generate_network_traffic_data(size: int, **kwargs) -> pd.DataFrame:
    """Generate network traffic demo data"""
    
    protocols = ['HTTP', 'HTTPS', 'FTP', 'SSH', 'DNS', 'SMTP']
    sources = [f"192.168.1.{i}" for i in range(1, 255)]
    destinations = [f"10.0.0.{i}" for i in range(1, 100)]
    
    data = []
    base_time = datetime.now() - timedelta(days=DEMO_DATA_CONFIG['date_range'])
    
    for i in range(size):
        timestamp = base_time + timedelta(
            seconds=random.randint(0, DEMO_DATA_CONFIG['date_range'] * 24 * 3600)
        )
        
        data.append({
            'timestamp': timestamp,
            'source_ip': random.choice(sources),
            'destination_ip': random.choice(destinations),
            'protocol': random.choice(protocols),
            'bytes_sent': random.randint(100, 10000),
            'bytes_received': random.randint(100, 5000),
            'duration': random.uniform(0.1, 30.0),
            'status': random.choice(['Success', 'Failed', 'Timeout'])
        })
    
    return pd.DataFrame(data)


def _generate_security_incidents_data(size: int, **kwargs) -> pd.DataFrame:
    """Generate security incidents demo data"""
    
    incident_types = [
        'Malware Detection', 'Phishing Attempt', 'Brute Force Attack',
        'Data Breach', 'Insider Threat', 'DDoS Attack', 'Vulnerability Exploit'
    ]
    
    severities = ['Low', 'Medium', 'High', 'Critical']
    statuses = ['Open', 'In Progress', 'Resolved', 'Closed']
    
    data = []
    base_time = datetime.now() - timedelta(days=DEMO_DATA_CONFIG['date_range'])
    
    for i in range(size):
        incident_time = base_time + timedelta(
            seconds=random.randint(0, DEMO_DATA_CONFIG['date_range'] * 24 * 3600)
        )
        
        data.append({
            'incident_id': f"INC-{i+1:04d}",
            'timestamp': incident_time,
            'type': random.choice(incident_types),
            'severity': random.choice(severities),
            'status': random.choice(statuses),
            'affected_systems': random.randint(1, 10),
            'source_ip': f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
            'description': f"Security incident involving {random.choice(incident_types).lower()}"
        })
    
    return pd.DataFrame(data)


def _generate_performance_metrics_data(size: int, **kwargs) -> pd.DataFrame:
    """Generate performance metrics demo data"""
    
    systems = ['Web Server', 'Database', 'Application Server', 'Load Balancer']
    metrics = ['CPU Usage', 'Memory Usage', 'Disk I/O', 'Network I/O']
    
    data = []
    base_time = datetime.now() - timedelta(hours=24)
    
    for i in range(size):
        timestamp = base_time + timedelta(minutes=i * (24 * 60 / size))
        
        for system in systems:
            for metric in metrics:
                if metric == 'CPU Usage':
                    value = random.uniform(10, 90)
                elif metric == 'Memory Usage':
                    value = random.uniform(20, 80)
                elif metric in ['Disk I/O', 'Network I/O']:
                    value = random.uniform(0, 100)
                
                data.append({
                    'timestamp': timestamp,
                    'system': system,
                    'metric': metric,
                    'value': value,
                    'unit': '%' if 'Usage' in metric else 'MB/s'
                })
    
    return pd.DataFrame(data)


def _generate_vulnerability_scan_data(size: int, **kwargs) -> pd.DataFrame:
    """Generate vulnerability scan demo data"""
    
    vulnerability_types = [
        'SQL Injection', 'Cross-Site Scripting', 'Buffer Overflow',
        'Privilege Escalation', 'Information Disclosure', 'Denial of Service'
    ]
    
    severities = ['Low', 'Medium', 'High', 'Critical']
    systems = [f"Server-{i:02d}" for i in range(1, 21)]
    
    data = []
    
    for i in range(size):
        data.append({
            'vulnerability_id': f"CVE-2023-{i+1000:04d}",
            'system': random.choice(systems),
            'type': random.choice(vulnerability_types),
            'severity': random.choice(severities),
            'cvss_score': round(random.uniform(1.0, 10.0), 1),
            'discovered_date': datetime.now() - timedelta(days=random.randint(1, 90)),
            'status': random.choice(['Open', 'Patched', 'Mitigated', 'False Positive']),
            'description': f"{random.choice(vulnerability_types)} vulnerability found in system"
        })
    
    return pd.DataFrame(data)


def _generate_user_activity_data(size: int, **kwargs) -> pd.DataFrame:
    """Generate user activity demo data"""
    
    users = [f"user{i:03d}" for i in range(1, 101)]
    activities = [
        'Login', 'Logout', 'File Access', 'File Modification', 'File Deletion',
        'Email Sent', 'Email Received', 'System Command', 'Database Query'
    ]
    
    data = []
    base_time = datetime.now() - timedelta(days=7)
    
    for i in range(size):
        timestamp = base_time + timedelta(
            seconds=random.randint(0, 7 * 24 * 3600)
        )
        
        data.append({
            'timestamp': timestamp,
            'user': random.choice(users),
            'activity': random.choice(activities),
            'source_ip': f"192.168.{random.randint(1,10)}.{random.randint(1,255)}",
            'success': random.choice([True, False]),
            'details': f"User performed {random.choice(activities).lower()} action"
        })
    
    return pd.DataFrame(data)


def calculate_security_score(metrics: Dict[str, float],
                           weights: Dict[str, float] = None) -> float:
    """Calculate overall security score from various metrics"""
    
    if weights is None:
        weights = {
            'vulnerability_count': -0.3,
            'patch_compliance': 0.25,
            'incident_response_time': -0.2,
            'user_training_completion': 0.15,
            'backup_success_rate': 0.1
        }
    
    score = 100  # Start with perfect score
    
    for metric, value in metrics.items():
        if metric in weights:
            weight = weights[metric]
            if weight > 0:  # Higher is better
                score += (value - 50) * weight  # Normalize around 50
            else:  # Lower is better
                score += (50 - value) * abs(weight)
    
    return max(0, min(100, score))  # Clamp between 0 and 100


def analyze_trends(data: pd.DataFrame,
                  value_column: str,
                  time_column: str = 'timestamp',
                  period: str = 'daily') -> Dict[str, Any]:
    """Analyze trends in time series data"""
    
    if time_column not in data.columns:
        raise ValueError(f"Time column '{time_column}' not found in data")
    
    if value_column not in data.columns:
        raise ValueError(f"Value column '{value_column}' not found in data")
    
    # Ensure datetime column
    data[time_column] = pd.to_datetime(data[time_column])
    
    # Group by period
    if period == 'hourly':
        data['period'] = data[time_column].dt.floor('H')
    elif period == 'daily':
        data['period'] = data[time_column].dt.date
    elif period == 'weekly':
        data['period'] = data[time_column].dt.to_period('W')
    elif period == 'monthly':
        data['period'] = data[time_column].dt.to_period('M')
    
    # Calculate trend statistics
    trend_data = data.groupby('period')[value_column].agg([
        'mean', 'min', 'max', 'std', 'count'
    ]).reset_index()
    
    # Calculate trend direction
    if len(trend_data) > 1:
        recent_avg = trend_data['mean'].tail(3).mean()
        earlier_avg = trend_data['mean'].head(3).mean()
        trend_direction = 'increasing' if recent_avg > earlier_avg else 'decreasing'
    else:
        trend_direction = 'stable'
    
    return {
        'trend_data': trend_data,
        'trend_direction': trend_direction,
        'overall_mean': data[value_column].mean(),
        'overall_std': data[value_column].std(),
        'data_points': len(data),
        'period_count': len(trend_data)
    }
