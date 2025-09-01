#!/usr/bin/env python3
"""
AI-Augmented Log Analysis System - Core Module
"""

import re
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass
from collections import Counter

@dataclass
class LogEntry:
    timestamp: datetime
    level: str
    source: str
    message: str
    ip_address: Optional[str] = None
    user: Optional[str] = None
    raw_log: str = ""

@dataclass
class Anomaly:
    type: str
    severity: str
    description: str
    count: int
    first_seen: datetime
    last_seen: datetime
    affected_resources: List[str]
    confidence: float

class LogParser:
    def __init__(self):
        self.ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        self.patterns = {
            'security': r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<source>\w+): (?P<message>.*)',
            'backup': r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<level>\w+)\s+(?P<job>\S+):\s+(?P<message>.*)',
            'apache': r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<size>\S+)'
        }
    
    def parse_log_file(self, filepath: str) -> List[LogEntry]:
        entries = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entry = self._parse_line(line)
                        if entry:
                            entries.append(entry)
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")
        return entries
    
    def _parse_line(self, line: str) -> Optional[LogEntry]:
        # Try security log pattern first
        security_match = re.search(self.patterns['security'], line)
        if security_match:
            groups = security_match.groupdict()
            return LogEntry(
                timestamp=self._parse_timestamp(groups['timestamp']),
                level=groups['level'],
                source=groups['source'],
                message=groups['message'],
                ip_address=self._extract_ip(line),
                user=self._extract_user(line),
                raw_log=line
            )
        
        # Try backup log pattern
        backup_match = re.search(self.patterns['backup'], line)
        if backup_match:
            groups = backup_match.groupdict()
            return LogEntry(
                timestamp=self._parse_timestamp(groups['timestamp']),
                level=groups['level'],
                source=groups['job'],
                message=groups['message'],
                raw_log=line
            )
        
        # Fallback
        return LogEntry(
            timestamp=datetime.now(),
            level='INFO',
            source='unknown',
            message=line,
            ip_address=self._extract_ip(line),
            user=self._extract_user(line),
            raw_log=line
        )
    
    def _parse_timestamp(self, ts_string: str) -> datetime:
        try:
            return datetime.strptime(ts_string, '%Y-%m-%d %H:%M:%S')
        except:
            return datetime.now()
    
    def _extract_ip(self, text: str) -> Optional[str]:
        match = re.search(self.ip_pattern, text)
        return match.group() if match else None
    
    def _extract_user(self, text: str) -> Optional[str]:
        match = re.search(r'user[:\s]+([a-zA-Z0-9_\-]+)', text, re.IGNORECASE)
        return match.group(1) if match else None

class AnomalyDetector:
    def __init__(self):
        self.failed_login_threshold = 3
    
    def detect_anomalies(self, logs: List[LogEntry]) -> List[Anomaly]:
        anomalies = []
        
        # Convert to DataFrame
        df = self._logs_to_dataframe(logs)
        
        if not df.empty:
            # Detect failed logins
            failed_logins = self._detect_failed_logins(df)
            anomalies.extend(failed_logins)
            
            # Detect errors
            errors = self._detect_errors(df)
            anomalies.extend(errors)
        
        return anomalies
    
    def _logs_to_dataframe(self, logs: List[LogEntry]) -> pd.DataFrame:
        data = []
        for log in logs:
            data.append({
                'timestamp': log.timestamp,
                'level': log.level,
                'source': log.source,
                'message': log.message,
                'ip_address': log.ip_address,
                'user': log.user
            })
        return pd.DataFrame(data)
    
    def _detect_failed_logins(self, df: pd.DataFrame) -> List[Anomaly]:
        anomalies = []
        
        failed_df = df[df['message'].str.contains('failed.*login|authentication.*failed', case=False, na=False)]
        
        if len(failed_df) >= self.failed_login_threshold:
            anomalies.append(Anomaly(
                type="Failed Login Attempts",
                severity="HIGH",
                description=f"Detected {len(failed_df)} failed login attempts",
                count=len(failed_df),
                first_seen=failed_df['timestamp'].min() if not failed_df.empty else datetime.now(),
                last_seen=failed_df['timestamp'].max() if not failed_df.empty else datetime.now(),
                affected_resources=["authentication_system"],
                confidence=0.9
            ))
        
        return anomalies
    
    def _detect_errors(self, df: pd.DataFrame) -> List[Anomaly]:
        anomalies = []
        
        error_df = df[df['level'].isin(['ERROR', 'CRITICAL'])]
        
        if len(error_df) > 5:
            anomalies.append(Anomaly(
                type="System Errors",
                severity="MEDIUM",
                description=f"Multiple system errors detected: {len(error_df)} errors",
                count=len(error_df),
                first_seen=error_df['timestamp'].min() if not error_df.empty else datetime.now(),
                last_seen=error_df['timestamp'].max() if not error_df.empty else datetime.now(),
                affected_resources=["system"],
                confidence=0.8
            ))
        
        return anomalies

class ThreatSummarizer:
    def generate_summary(self, anomalies: List[Anomaly]) -> Dict:
        if not anomalies:
            return {
                'overall_risk': 'LOW',
                'summary': 'No significant threats detected in analyzed logs.',
                'recommendations': ['Continue monitoring system logs regularly'],
                'statistics': {
                    'total_anomalies': 0,
                    'high_severity': 0,
                    'medium_severity': 0,
                    'low_severity': 0
                }
            }
        
        severity_counts = Counter(a.severity for a in anomalies)
        risk_score = len(anomalies)
        
        if risk_score < 3:
            overall_risk = 'LOW'
        elif risk_score < 8:
            overall_risk = 'MEDIUM'
        else:
            overall_risk = 'HIGH'
        
        return {
            'overall_risk': overall_risk,
            'summary': f'Analysis detected {len(anomalies)} security anomalies requiring attention.',
            'recommendations': [
                'Review failed authentication attempts',
                'Investigate system error patterns',
                'Implement additional monitoring',
                'Consider security policy updates'
            ],
            'statistics': {
                'total_anomalies': len(anomalies),
                'high_severity': severity_counts.get('HIGH', 0),
                'medium_severity': severity_counts.get('MEDIUM', 0),
                'low_severity': severity_counts.get('LOW', 0)
            }
        }

if __name__ == "__main__":
    print("✅ Log Analyzer module loaded successfully!")
    
    # Test with sample data
    parser = LogParser()
    detector = AnomalyDetector()
    summarizer = ThreatSummarizer()
    
    print("🔧 Components initialized and ready!")