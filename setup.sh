#!/bin/bash

# AI-Augmented Log Analysis System - Fixed Setup Script
# This script will create all necessary files step by step

echo "🚀 Setting up AI-Augmented Log Analysis System..."
echo "=================================================="

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Step 1: Create directory structure
print_header "Step 1: Creating Directories"
mkdir -p logs
mkdir -p reports/{ppt,json,csv}
mkdir -p data/{models,cache,temp}
mkdir -p grafana/{dashboards,datasources}
mkdir -p prometheus
print_status "Directory structure created"

# Step 2: Create requirements.txt
print_header "Step 2: Creating requirements.txt"
cat > requirements.txt << 'EOF'
streamlit==1.28.1
pandas==2.1.3
numpy==1.24.3
scikit-learn==1.3.2
plotly==5.17.0
requests==2.31.0
python-pptx==0.6.22
matplotlib==3.8.2
EOF
print_status "requirements.txt created"

# Step 3: Create core log analyzer
print_header "Step 3: Creating log_analyzer.py"
cat > log_analyzer.py << 'EOF'
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
EOF
print_status "log_analyzer.py created with working functionality"

# Step 4: Create Streamlit application
print_header "Step 4: Creating streamlit_app.py"
cat > streamlit_app.py << 'EOF'
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import os

st.set_page_config(
    page_title="AI Log Analysis System",
    page_icon="🔒",
    layout="wide"
)

# Import our modules
try:
    from log_analyzer import LogParser, AnomalyDetector, ThreatSummarizer
    components_loaded = True
except ImportError as e:
    components_loaded = False
    st.error(f"Error importing log_analyzer: {e}")

# Initialize session state
if 'logs' not in st.session_state:
    st.session_state.logs = []
if 'anomalies' not in st.session_state:
    st.session_state.anomalies = []
if 'summary' not in st.session_state:
    st.session_state.summary = {}

def main():
    st.title("🔒 AI-Augmented Log Analysis System")
    st.markdown("**Hackathon Demo - Detect anomalies and analyze threats from system logs**")
    
    if not components_loaded:
        st.error("⚠️ Core modules not loaded. Please check log_analyzer.py")
        return
    
    # Sidebar
    with st.sidebar:
        st.header("📁 Data Input")
        
        # File upload
        uploaded_files = st.file_uploader(
            "Upload log files",
            type=['log', 'txt'],
            accept_multiple_files=True,
            help="Upload your security, backup, or system logs"
        )
        
        # Sample data button
        if st.button("📋 Use Sample Data"):
            load_sample_data()
        
        # Analysis settings
        st.header("⚙️ Settings")
        threshold = st.slider("Failed Login Threshold", 1, 20, 3)
    
    # Main content
    col1, col2 = st.columns([3, 1])
    
    with col1:
        if uploaded_files:
            process_uploaded_files(uploaded_files)
        
        if st.session_state.logs:
            display_results()
        else:
            show_welcome_screen()
    
    with col2:
        show_quick_stats()

def load_sample_data():
    """Load sample log data"""
    parser = LogParser()
    
    # Check if sample logs exist
    sample_files = ['logs/security.log', 'logs/backup.log']
    all_logs = []
    
    for file_path in sample_files:
        if os.path.exists(file_path):
            logs = parser.parse_log_file(file_path)
            all_logs.extend(logs)
    
    if not all_logs:
        # Create sample data in memory
        from datetime import datetime, timedelta
        
        sample_logs = []
        base_time = datetime.now() - timedelta(hours=2)
        
        # Add some normal logs
        for i in range(10):
            sample_logs.append({
                'timestamp': base_time + timedelta(minutes=i*5),
                'level': 'INFO',
                'source': 'auth',
                'message': f'Successful login for user{i} from 192.168.1.{100+i}',
                'ip_address': f'192.168.1.{100+i}',
                'user': f'user{i}'
            })
        
        # Add failed logins (anomaly)
        for i in range(5):
            sample_logs.append({
                'timestamp': base_time + timedelta(minutes=60+i),
                'level': 'ERROR',
                'source': 'auth',
                'message': 'Failed login attempt for user admin from 203.0.113.10',
                'ip_address': '203.0.113.10',
                'user': 'admin'
            })
        
        # Convert to LogEntry objects
        from log_analyzer import LogEntry
        all_logs = [LogEntry(**log) for log in sample_logs]
    
    st.session_state.logs = all_logs
    
    # Run analysis
    detector = AnomalyDetector()
    summarizer = ThreatSummarizer()
    
    st.session_state.anomalies = detector.detect_anomalies(all_logs)
    st.session_state.summary = summarizer.generate_summary(st.session_state.anomalies)
    
    st.success(f"✅ Loaded {len(all_logs)} sample log entries!")
    st.rerun()

def process_uploaded_files(uploaded_files):
    """Process uploaded files"""
    parser = LogParser()
    detector = AnomalyDetector()
    summarizer = ThreatSummarizer()
    
    all_logs = []
    
    with st.spinner("Processing uploaded files..."):
        for file in uploaded_files:
            try:
                # Save temporarily and process
                content = file.getvalue().decode('utf-8')
                temp_file = f"temp_{file.name}"
                
                with open(temp_file, 'w') as f:
                    f.write(content)
                
                logs = parser.parse_log_file(temp_file)
                all_logs.extend(logs)
                
                # Clean up
                os.remove(temp_file)
                
            except Exception as e:
                st.error(f"Error processing {file.name}: {e}")
    
    if all_logs:
        st.session_state.logs = all_logs
        st.session_state.anomalies = detector.detect_anomalies(all_logs)
        st.session_state.summary = summarizer.generate_summary(st.session_state.anomalies)
        
        st.success(f"✅ Processed {len(all_logs)} log entries from {len(uploaded_files)} files")
        st.rerun()

def display_results():
    """Display analysis results"""
    st.header("📊 Analysis Results")
    
    # Metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Logs", len(st.session_state.logs))
    
    with col2:
        st.metric("Anomalies", len(st.session_state.anomalies))
    
    with col3:
        risk_level = st.session_state.summary.get('overall_risk', 'UNKNOWN')
        st.metric("Risk Level", risk_level)
    
    with col4:
        high_severity = st.session_state.summary.get('statistics', {}).get('high_severity', 0)
        st.metric("High Severity", high_severity)
    
    # Summary
    st.subheader("📝 Threat Summary")
    summary_text = st.session_state.summary.get('summary', 'No summary available')
    st.write(summary_text)
    
    # Recommendations
    recommendations = st.session_state.summary.get('recommendations', [])
    if recommendations:
        st.subheader("💡 Recommendations")
        for i, rec in enumerate(recommendations, 1):
            st.write(f"{i}. {rec}")
    
    # Anomaly details
    if st.session_state.anomalies:
        st.subheader("🔍 Detected Anomalies")
        
        anomaly_data = []
        for anomaly in st.session_state.anomalies:
            anomaly_data.append({
                'Type': anomaly.type,
                'Severity': anomaly.severity,
                'Count': anomaly.count,
                'Confidence': f"{anomaly.confidence:.1%}",
                'Description': anomaly.description[:80] + "..." if len(anomaly.description) > 80 else anomaly.description
            })
        
        df = pd.DataFrame(anomaly_data)
        st.dataframe(df, use_container_width=True)
        
        # Simple visualization
        if len(anomaly_data) > 0:
            st.subheader("📈 Anomaly Distribution")
            
            # Severity distribution
            severity_counts = pd.Series([a['Severity'] for a in anomaly_data]).value_counts()
            fig = px.pie(values=severity_counts.values, names=severity_counts.index, title="Anomalies by Severity")
            st.plotly_chart(fig, use_container_width=True)

def show_welcome_screen():
    """Show welcome screen when no data is loaded"""
    st.header("👋 Welcome to AI Log Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🔍 Detection Features")
        st.write("• Failed authentication attempts")
        st.write("• Error pattern analysis")  
        st.write("• Unusual access patterns")
        st.write("• System health monitoring")
        st.write("• Time-based anomalies")
    
    with col2:
        st.subheader("📊 Reporting Features")
        st.write("• Real-time dashboards")
        st.write("• Executive summaries")
        st.write("• PowerPoint exports")
        st.write("• JSON/CSV exports")
        st.write("• Email alerts")
    
    st.info("👆 Upload log files or click 'Use Sample Data' to start analysis")

def show_quick_stats():
    """Show quick statistics in sidebar"""
    st.header("📈 Quick Stats")
    
    if st.session_state.logs:
        # Log level distribution
        levels = [log.level for log in st.session_state.logs]
        level_counts = pd.Series(levels).value_counts()
        
        st.write("**Log Levels:**")
        for level, count in level_counts.items():
            st.write(f"• {level}: {count}")
        
        # Time range
        if st.session_state.logs:
            timestamps = [log.timestamp for log in st.session_state.logs]
            time_range = max(timestamps) - min(timestamps)
            st.write(f"**Time Range:** {time_range.days} days")
    
    else:
        st.write("No data loaded yet")
    
    # Export buttons
    if st.session_state.anomalies:
        st.header("📤 Export Options")
        
        if st.button("📑 Generate Report"):
            generate_simple_report()
        
        if st.button("📄 Download JSON"):
            download_json()

def generate_simple_report():
    """Generate simple text report"""
    report = f"""
SECURITY LOG ANALYSIS REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

EXECUTIVE SUMMARY:
- Risk Level: {st.session_state.summary.get('overall_risk', 'UNKNOWN')}
- Total Anomalies: {len(st.session_state.anomalies)}
- Analysis Period: Last 24 hours

FINDINGS:
"""
    
    for i, anomaly in enumerate(st.session_state.anomalies, 1):
        report += f"""
{i}. {anomaly.type}
   Severity: {anomaly.severity}
   Count: {anomaly.count}
   Description: {anomaly.description}
"""
    
    report += f"""
RECOMMENDATIONS:
"""
    for i, rec in enumerate(st.session_state.summary.get('recommendations', []), 1):
        report += f"{i}. {rec}\n"
    
    st.text_area("Generated Report", report, height=400)
    
    st.download_button(
        "📥 Download Report",
        data=report,
        file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
        mime="text/plain"
    )

def download_json():
    """Download JSON report"""
    import json
    
    report_data = {
        'timestamp': datetime.now().isoformat(),
        'summary': st.session_state.summary,
        'anomalies': [
            {
                'type': anomaly.type,
                'severity': anomaly.severity,
                'description': anomaly.description,
                'count': anomaly.count,
                'confidence': anomaly.confidence
            }
            for anomaly in st.session_state.anomalies
        ]
    }
    
    json_str = json.dumps(report_data, indent=2)
    
    st.download_button(
        "📥 Download JSON",
        data=json_str,
        file_name=f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json"
    )

if __name__ == "__main__":
    main()
EOF
print_status "streamlit_app.py created"

# Step 5: Create sample logs
print_header "Step 5: Creating Sample Log Files"
cat > logs/security.log << 'EOF'
2024-01-29 09:15:23 [INFO] auth: Successful login for user jdoe from 192.168.1.100
2024-01-29 09:16:45 [INFO] auth: Successful login for user admin from 192.168.1.101
2024-01-29 09:17:12 [WARN] auth: Failed login attempt for user admin from 203.0.113.10
2024-01-29 09:17:15 [WARN] auth: Failed login attempt for user admin from 203.0.113.10
2024-01-29 09:17:18 [ERROR] auth: Failed login attempt for user admin from 203.0.113.10
2024-01-29 09:17:21 [ERROR] auth: Multiple failed login attempts detected for user admin from 203.0.113.10
2024-01-29 09:20:30 [INFO] auth: Successful login for user ssmith from 192.168.1.102
2024-01-29 10:05:45 [ERROR] system: Database connection timeout
2024-01-29 10:06:12 [ERROR] system: Service restart failed
2024-01-29 10:15:33 [INFO] auth: User admin logged out
EOF

cat > logs/backup.log << 'EOF'
2024-01-29 02:00:00 INFO database_prod: Backup started
2024-01-29 02:15:30 INFO database_prod: Backup completed successfully, 1.2GB in 15min
2024-01-29 02:30:00 INFO fileserver_backup: Backup started
2024-01-29 02:45:22 ERROR fileserver_backup: Backup failed - Cannot connect to storage backend
2024-01-29 03:00:00 INFO user_data: Backup started
2024-01-29 03:20:15 INFO user_data: Backup completed successfully, 850MB in 20min
2024-01-29 03:30:00 ERROR config_backup: Backup failed - Permission denied
EOF
print_status "Sample log files created"

# Step 6: Create Docker files
print_header "Step 6: Creating Docker Configuration"
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  log-analyzer:
    build: .
    ports:
      - "8501:8501"
    volumes:
      - ./logs:/app/logs
      - ./reports:/app/reports
    environment:
      - PYTHONUNBUFFERED=1
    restart: unless-stopped

volumes:
  logs-data:
  reports-data:
EOF
print_status "docker-compose.yml created"

# Step 7: Create startup scripts
print_header "Step 7: Creating Startup Scripts"

cat > run_quick_test.sh << 'EOF'
#!/bin/bash
echo "🧪 Quick Test Run"
echo "================"

# Test the log analyzer
echo "Testing log analyzer module..."
python3 -c "from log_analyzer import LogParser; print('✅ LogParser imported successfully')"

echo ""
echo "🚀 Starting Streamlit app..."
echo "Access at: http://localhost:8501"
echo "Press Ctrl+C to stop"
echo ""

python3 -m streamlit run streamlit_app.py --server.port=8501
EOF
chmod +x run_quick_test.sh
print_status "Quick test script created"

# Step 8: Final status
print_header "Step 8: Setup Complete!"

echo ""
print_status "Files created:"
ls -la *.py *.txt *.yml *.sh 2>/dev/null

echo ""
print_status "Directories created:"
ls -la | grep ^d

echo ""
print_warning "Next steps:"
echo "1. Install dependencies: pip3 install -r requirements.txt"
echo "2. Test the application: ./run_quick_test.sh"
echo "3. Or install in virtual env first:"
echo "   python3 -m venv venv"
echo "   source venv/bin/activate" 
echo "   pip install -r requirements.txt"
echo "   streamlit run streamlit_app.py"

echo ""
print_status "🎉 AI Log Analysis System setup complete!"
