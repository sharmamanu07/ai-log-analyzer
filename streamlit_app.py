import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime

# PPT Generation Entries

from ppt_generator import create_security_report
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

# Adding a Button for PPT Report Generation

        if st.button("📊 Download PPT Report"):
            download_ppt()

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

# Download PPT Generation Code

def download_ppt():
    """Generate and download PowerPoint report"""
    ppt_bytes = create_security_report(
        st.session_state.summary,
        st.session_state.anomalies,
        st.session_state.logs
    )

    st.download_button(
        "📥 Download PPT",
        data=ppt_bytes,
        file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pptx",
        mime="application/vnd.openxmlformats-officedocument.presentationml.presentation"
    )


if __name__ == "__main__":
    main()
