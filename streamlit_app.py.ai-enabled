import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import os

# PPT Generation Entries
from ppt_generator import create_security_report

# LLM Integration
import requests

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
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

def main():
    st.title("🔒 AI-Augmented Log Analysis System")
    st.markdown("**Hackathon Demo - Detect anomalies and analyze threats from system logs**")
    
    if not components_loaded:
        st.error("⚠️ Core modules not loaded. Please check log_analyzer.py")
        return
    
    # Create tabs for different views
    tab1, tab2, tab3 = st.tabs(["📊 Dashboard", "🤖 AI Chat", "⚙️ Settings"])

    with tab1:
        show_dashboard()

    with tab2:
        show_ai_chat()

    with tab3:
        show_settings()

def show_dashboard():

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

def show_ai_chat():
    """AI Chat interface for natural language queries"""
    st.header("🤖 AI Security Assistant")
    st.markdown("Ask questions about your log data in natural language!")

    # Check if data is loaded
    if not st.session_state.logs:
        st.warning("⚠️ Please load log data first in the Dashboard tab")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("📋 Load Sample Data", key="chat_sample"):
                load_sample_data()
                st.rerun()

        return

    # AI Engine Status
    col1, col2 = st.columns([3, 1])

    with col2:
        st.subheader("🔧 AI Engine")

        # Check for external LLM services
        ollama_status = check_ollama_connection()

        if ollama_status['available']:
            st.success(f"🟢 Ollama: Connected")
            st.write(f"Model: {ollama_status.get('model', 'llama2')}")
        else:
            st.warning("🟡 Ollama: Not available")

        # Always show built-in processor
        st.success("🟢 Built-in NLP: Ready")

        st.write("**Capabilities:**")
        st.write("• Security pattern analysis")
        st.write("• Threat summarization")
        st.write("• Natural language responses")
        st.write("• Context-aware insights")

    with col1:
        # Example queries
        st.subheader("💡 Example Queries")

        example_queries = [
            "Summarize top 3 suspicious activities in last 24h",
            "Which vaults had most failed restores this week?",
            "What are the most common authentication failures?",
            "Show me unusual access patterns from external IPs",
            "Are there any brute force attacks detected?",
            "What security incidents need immediate attention?"
        ]

        # Create example query buttons
        cols = st.columns(2)
        for i, example in enumerate(example_queries):
            with cols[i % 2]:
                if st.button(f"💬 {example[:35]}{'...' if len(example) > 35 else ''}", key=f"example_{i}"):
                    # Add to chat and process
                    st.session_state.chat_history.append({
                        'type': 'user',
                        'content': example,
                        'timestamp': datetime.now()
                    })
                    process_ai_query(example)
                    st.rerun()

        st.markdown("---")

        # Custom query input
        st.subheader("💬 Ask Your Question")

        user_query = st.text_area(
            "Enter your question about the log data:",
            placeholder="e.g., What happened between 2PM and 4PM today? Are there patterns in failed logins?",
            height=80,
            key="user_query_input"
        )

        col_ask, col_clear = st.columns([3, 1])

        with col_ask:
            if st.button("🚀 Ask AI", key="ask_button", disabled=not user_query.strip()):
                if user_query.strip():
                    # Add user query to chat history
                    st.session_state.chat_history.append({
                        'type': 'user',
                        'content': user_query,
                        'timestamp': datetime.now()
                    })

                    # Process the query
                    process_ai_query(user_query)
                    st.rerun()

        with col_clear:
            if st.button("🧹 Clear Chat", key="clear_chat"):
                st.session_state.chat_history = []
                st.rerun()

        # Display chat history
        st.subheader("💬 Chat History")

        if st.session_state.chat_history:
            # Show recent messages (last 10 exchanges)
            recent_messages = list(reversed(st.session_state.chat_history[-20:]))

            for message in recent_messages:
                timestamp = message['timestamp'].strftime("%H:%M:%S")

                if message['type'] == 'user':
                    st.markdown(f"**👤 You ({timestamp}):**")
                    st.markdown(f"> {message['content']}")
                else:
                    with st.container():
                        st.markdown(f"**🤖 AI Assistant ({timestamp}):**")
                        st.markdown(message['content'])

                st.markdown("---")
        else:
            st.info("💡 Start a conversation by asking a question or clicking an example above!")

def show_settings():
    """Settings and configuration"""
    st.header("⚙️ System Configuration")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("🐳 Container Information")

        # Container environment info
        st.write("**Environment:**")
        if os.path.exists('/.dockerenv'):
            st.success("✅ Running in Docker container")
        else:
            st.info("🔵 Running locally")

        # Network connectivity
        st.write("**Network Connectivity:**")

        # Test external services
        ollama_status = check_ollama_connection()
        if ollama_status['available']:
            st.success(f"✅ Ollama: {ollama_status['url']}")
        else:
            st.warning("⚠️ Ollama: Not accessible")
            st.caption("Try: docker run -d -p 11434:11434 ollama/ollama")

        # Test internet connectivity
        try:
            response = requests.get("https://httpbin.org/status/200", timeout=5)
            if response.status_code == 200:
                st.success("✅ Internet: Connected")
            else:
                st.warning("⚠️ Internet: Limited")
        except:
            st.warning("⚠️ Internet: Not available")

    with col2:
        st.subheader("📊 Analysis Configuration")

        # Detection settings
        failed_login_threshold = st.number_input("Failed Login Threshold", 1, 50, 3)
        error_spike_threshold = st.number_input("Error Spike Threshold", 1, 20, 5)
        confidence_threshold = st.slider("Minimum Confidence", 0.0, 1.0, 0.7)

        if st.button("💾 Save Settings"):
            st.session_state.settings = {
                'failed_login_threshold': failed_login_threshold,
                'error_spike_threshold': error_spike_threshold,
                'confidence_threshold': confidence_threshold
            }
            st.success("✅ Settings saved!")

def check_ollama_connection():
    """Check if Ollama service is available"""
    possible_urls = [
        os.getenv('OLLAMA_URL', 'http://ollama:11434'),
        "http://host.docker.internal:11434",  # Docker Desktop
        "http://ollama:11434",                # Docker Compose
        "http://localhost:11434",             # Local
        "http://172.17.0.1:11434",           # Docker bridge
    ]

    for url in possible_urls:
        try:
            response = requests.get(f"{url}/api/tags", timeout=3)
            if response.status_code == 200:
                return {
                    'available': True,
                    'url': url,
                    'model': 'llama2'  # Default model
                }
        except:
            continue

    return {'available': False}

def query_ollama(prompt: str, context: dict = None) -> str:
    """Query external Ollama service"""
    ollama_status = check_ollama_connection()

    if not ollama_status['available']:
        return None

    try:
        # Prepare context-aware prompt
        full_prompt = f"""You are a cybersecurity analyst. Answer briefly and clearly.

Query: {prompt}

Context: You are analyzing security logs with {len(st.session_state.logs)} entries and {len(st.session_state.anomalies)} anomalies detected.
Risk Level: {st.session_state.summary.get('overall_risk', 'Unknown')}

Provide a professional, concise security analysis:"""

        if context and st.session_state.anomalies:
            full_prompt += "\n\nKey Issues:\n"
            for anomaly in st.session_state.anomalies[:3]:
                full_prompt += f"- {anomaly.type}: {anomaly.severity}, {anomaly.count} events\n"

        response = requests.post(
            f"{ollama_status['url']}/api/generate",
            json={
                "model": "llama2",
                "prompt": full_prompt,
                "stream": False,
                "options": {
                    "temperature": 0.3,
                    "max_tokens": 300
                }
            },
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            return result.get('response', 'No response generated')

    except Exception as e:
        return f"LLM service error: {str(e)}"

    return None

def process_ai_query(query: str):
    """Process AI query and add response to chat history"""

    # Try Ollama first, then fallback to built-in responses
    llm_response = query_ollama(query, {'anomalies': st.session_state.anomalies})

    if llm_response and not llm_response.startswith("LLM service error"):
        response = llm_response
    else:
        # Use built-in intelligent responses
        response = generate_intelligent_response(query)

    # Add AI response to chat history
    st.session_state.chat_history.append({
        'type': 'assistant',
        'content': response,
        'timestamp': datetime.now()
    })

def generate_intelligent_response(query: str) -> str:
    """Generate intelligent response based on log analysis"""

    query_lower = query.lower()

    # Suspicious activities query
    if any(word in query_lower for word in ["suspicious", "top 3", "threat"]):
        return generate_suspicious_response()

    # Vault/backup query
    elif any(word in query_lower for word in ["vault", "backup", "restore"]):
        return generate_vault_response()

    # Authentication query
    elif any(word in query_lower for word in ["login", "auth", "credential", "brute force"]):
        return generate_auth_response()

    # General summary
    elif any(word in query_lower for word in ["summary", "overview", "status"]):
        return generate_summary_response()

    # Pattern analysis
    elif any(word in query_lower for word in ["pattern", "unusual", "access"]):
        return generate_pattern_response()

    # Default response
    else:
        return generate_general_response()

def generate_suspicious_response() -> str:
    """Generate response about suspicious activities"""
    if not st.session_state.anomalies:
        return "📊 **Suspicious Activities Analysis:**\n\nNo suspicious activities detected in the current analysis. The system appears to be operating normally without significant security anomalies."

    # Sort by severity and confidence
    severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    top_anomalies = sorted(
        st.session_state.anomalies,
        key=lambda x: (severity_order.get(x.severity, 0), x.confidence),
        reverse=True
    )[:3]

    response = "🔍 **Top 3 Suspicious Activities:**\n\n"

    for i, anomaly in enumerate(top_anomalies, 1):
        risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(anomaly.severity, "⚪")

        response += f"**{i}. {anomaly.type}** {risk_emoji}\n"
        response += f"   • **Severity:** {anomaly.severity}\n"
        response += f"   • **Occurrences:** {anomaly.count}\n"
        response += f"   • **Confidence:** {anomaly.confidence:.1%}\n"
        response += f"   • **Timeline:** {anomaly.first_seen.strftime('%H:%M')} - {anomaly.last_seen.strftime('%H:%M')}\n"
        response += f"   • **Details:** {anomaly.description[:100]}{'...' if len(anomaly.description) > 100 else ''}\n\n"

    response += "💡 **Recommendation:** Prioritize investigation of high-severity issues and implement additional monitoring."
    return response

def generate_vault_response() -> str:
    """Generate response about vault/backup issues"""
    vault_anomalies = [a for a in st.session_state.anomalies
                      if any(term in a.type.lower() for term in ['vault', 'backup', 'restore'])]

    if not vault_anomalies:
        return "🗄️ **Vault/Backup Analysis:**\n\nNo vault or backup failures detected. Your backup systems appear to be functioning properly."

    response = "🗄️ **Vault/Backup System Analysis:**\n\n"

    total_failures = sum(a.count for a in vault_anomalies)
    critical_failures = [a for a in vault_anomalies if a.severity in ['HIGH', 'CRITICAL']]

    response += f"• **Total backup/vault issues:** {total_failures}\n"
    response += f"• **Critical failures:** {len(critical_failures)}\n\n"

    response += "**Issue Breakdown:**\n"
    for anomaly in vault_anomalies[:3]:
        response += f"• **{anomaly.type}:** {anomaly.count} occurrences\n"
        response += f"  Severity: {anomaly.severity}, Confidence: {anomaly.confidence:.1%}\n"
        if anomaly.affected_resources:
            response += f"  Affected: {', '.join(anomaly.affected_resources[:2])}\n"
        response += "\n"

    response += "💡 **Recommendation:** Review backup procedures and ensure redundancy for critical systems."
    return response

def generate_auth_response() -> str:
    """Generate response about authentication issues"""
    auth_anomalies = [a for a in st.session_state.anomalies
                     if any(term in a.type.lower() for term in ['login', 'auth', 'access'])]

    response = "🔐 **Authentication Security Analysis:**\n\n"

    if not auth_anomalies:
        response += "No significant authentication anomalies detected. Login patterns appear normal.\n\n"
        response += "**Security Status:** ✅ Good\n"
        response += "• No brute force attacks detected\n"
        response += "• Authentication rates within normal parameters\n"
    else:
        total_failed = sum(a.count for a in auth_anomalies)
        high_severity = [a for a in auth_anomalies if a.severity in ['HIGH', 'CRITICAL']]

        response += f"• **Suspicious authentication events:** {total_failed}\n"
        response += f"• **High-priority threats:** {len(high_severity)}\n\n"

        if high_severity:
            response += "🚨 **Critical Issues:**\n"
            for anomaly in high_severity:
                response += f"• {anomaly.description}\n"
                response += f"  Count: {anomaly.count}, Confidence: {anomaly.confidence:.1%}\n\n"

        # Check for brute force patterns
        brute_force = [a for a in auth_anomalies if 'failed' in a.description.lower() and a.count >= 5]
        if brute_force:
            response += "⚠️ **Potential brute force attacks detected!**\n\n"

        response += "💡 **Immediate Actions:**\n"
        response += "• Review failed authentication sources\n"
        response += "• Implement account lockout policies\n"
        response += "• Consider IP-based blocking for repeat offenders\n"

    return response

def generate_summary_response() -> str:
    """Generate general summary response"""
    total_logs = len(st.session_state.logs)
    total_anomalies = len(st.session_state.anomalies)
    risk_level = st.session_state.summary.get('overall_risk', 'UNKNOWN')

    risk_emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(risk_level, "⚪")

    response = f"📊 **Security Analysis Summary:**\n\n"
    response += f"• **Data Analyzed:** {total_logs:,} log entries\n"
    response += f"• **Anomalies Found:** {total_anomalies}\n"
    response += f"• **Risk Assessment:** {risk_level} {risk_emoji}\n\n"

    if st.session_state.anomalies:
        # Count by severity
        severity_counts = {}
        for anomaly in st.session_state.anomalies:
            severity_counts[anomaly.severity] = severity_counts.get(anomaly.severity, 0) + 1

        response += "**Issues by Severity:**\n"
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[severity]
                response += f"• {severity}: {count} {emoji}\n"

        response += "\n**Top Issue Types:**\n"
        anomaly_types = {}
        for anomaly in st.session_state.anomalies:
            anomaly_types[anomaly.type] = anomaly_types.get(anomaly.type, 0) + 1

        for anomaly_type, count in sorted(anomaly_types.items(), key=lambda x: x[1], reverse=True)[:3]:
            response += f"• {anomaly_type}: {count} incidents\n"
    else:
        response += "✅ **Good News:** No security anomalies detected!\n"

    # Add time range
    if st.session_state.logs:
        timestamps = [log.timestamp for log in st.session_state.logs]
        time_range = max(timestamps) - min(timestamps)
        response += f"\n**Analysis Period:** {time_range.days} days of log data\n"

    return response

def generate_pattern_response() -> str:
    """Generate response about access patterns"""
    response = "🔍 **Access Pattern Analysis:**\n\n"

    if not st.session_state.logs:
        return response + "No log data available for pattern analysis."

    # Analyze IP patterns
    ip_addresses = [log.ip_address for log in st.session_state.logs if log.ip_address]
    if ip_addresses:
        unique_ips = len(set(ip_addresses))
        response += f"• **Unique IP addresses:** {unique_ips}\n"

        # Most active IPs
        from collections import Counter
        ip_counts = Counter(ip_addresses)
        top_ips = ip_counts.most_common(3)

        response += "• **Most active IPs:**\n"
        for ip, count in top_ips:
            response += f"  - {ip}: {count} requests\n"

    # Analyze time patterns
    hours = [log.timestamp.hour for log in st.session_state.logs]
    if hours:
        from collections import Counter
        hour_counts = Counter(hours)
        peak_hour = hour_counts.most_common(1)[0]
        
        response += f"\n• **Peak activity hour:** {peak_hour[0]}:00 ({peak_hour[1]} events)\n"
        
        # Check for off-hours activity
        off_hours_activity = sum(1 for h in hours if h < 6 or h > 22)
        if off_hours_activity > 0:
            percentage = (off_hours_activity / len(hours)) * 100
            response += f"• **Off-hours activity:** {off_hours_activity} events ({percentage:.1f}%)\n"
    
    # Check for unusual patterns
    unusual_patterns = [a for a in st.session_state.anomalies 
                       if 'pattern' in a.type.lower() or 'unusual' in a.type.lower()]
    
    if unusual_patterns:
        response += f"\n🚨 **Unusual patterns detected:** {len(unusual_patterns)}\n"
        for pattern in unusual_patterns[:2]:
            response += f"• {pattern.description}\n"
    
    response += "\n💡 **Pattern Analysis Insights:**\n"
    response += "• Monitor peak activity periods for capacity planning\n"
    response += "• Investigate excessive off-hours activity\n"
    response += "• Track IP reputation for external addresses\n"
    
    return response

def generate_general_response() -> str:
    """Generate general response for unclassified queries"""
    return f"""🔍 **AI Log Analysis Assistant:**

I've analyzed your security logs and here's what I can help you with:

**📊 Current Analysis Status:**
• Log entries processed: {len(st.session_state.logs):,}
• Security anomalies detected: {len(st.session_state.anomalies)}
• Risk level: {st.session_state.summary.get('overall_risk', 'Unknown')}

**🎯 What you can ask me:**
• **"Top suspicious activities"** - Get prioritized security threats
• **"Authentication issues"** - Review login failures and access problems
• **"Backup system status"** - Check backup and restore operations
• **"Access patterns"** - Analyze user and IP behavior
• **"System health summary"** - Overall security posture

**💡 Pro tip:** Be specific! Ask things like "Show me failed logins from external IPs" or "What backup failures happened this week?"

What specific aspect of your security logs would you like me to analyze?"""


if __name__ == "__main__":
    main()
