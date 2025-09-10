import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import os
import json

# PPT Generation Entries
from ppt_generator import create_security_report

# LLM Integration
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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

        # Visualization
        if len(anomaly_data) > 0:
            st.subheader("📈 Anomaly Distribution")

            # Convert to DataFrame for easier aggregation
            df_vis = pd.DataFrame(anomaly_data)

            # Normalize severity labels
            df_vis["Severity"] = df_vis["Severity"].astype(str).str.strip().str.upper()
            df_vis["Severity"] = df_vis["Severity"].replace({"CRIT": "CRITICAL"})

            # Aggregate counts by severity (more accurate than row counts)
            severity_counts = (
                df_vis.groupby("Severity")["Count"]
                .sum()
                .reindex(["CRITICAL", "HIGH", "MEDIUM", "LOW"], fill_value=0)
            )

            # Build pie chart
            fig = px.pie(
                values=severity_counts.values,
                names=severity_counts.index,
                title="Events by Severity",
                color=severity_counts.index,
                color_discrete_map={
                    "CRITICAL": "darkred",
                    "HIGH": "red",
                    "MEDIUM": "orange",
                    "LOW": "green",
                },
            )
            fig.update_traces(textinfo="percent+label")
            st.plotly_chart(fig, use_container_width=True)

            # --- Bar chart: Anomalies by Type ---
            type_counts = df_vis.groupby("Type")["Count"].sum().sort_values(ascending=False)

            fig_bar = px.bar(
                x=type_counts.index,
                y=type_counts.values,
                labels={"x": "Anomaly Type", "y": "Occurrences"},
                title="Anomalies by Type",
                text=type_counts.values,
            )
            fig_bar.update_traces(textposition="outside")
            fig_bar.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig_bar, use_container_width=True)

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

    # AI Engine Status + Example queries
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

        # Example Queries
        st.subheader("💡 Example Queries")

        example_queries = [
            "Summarize top 3 suspicious activities in last 24h",
            "Which vaults had most failed restores this week?",
            "What are the most common authentication failures?",
            "Show me unusual access patterns from external IPs",
            "Are there any brute force attacks detected?",
            "What security incidents need immediate attention?"
        ]

        for i, example in enumerate(example_queries):
            if st.button(f"💬 {example[:35]}{'...' if len(example) > 35 else ''}", key=f"example_{i}"):
                st.session_state.chat_history.append({
                    'role': 'user',
                    'content': example,
                    'timestamp': datetime.now()
                })
                process_ai_query(example)
                st.rerun()

        st.markdown("---")
        st.write("**Capabilities:**")
        st.write("• Security pattern analysis")
        st.write("• Threat summarization")
        st.write("• Natural language responses")
        st.write("• Context-aware insights")

    with col1:
        # Display chat history first (like ChatGPT)
        st.subheader("💬 Conversation")

        if st.session_state.chat_history:
            for message in st.session_state.chat_history[-20:]:
                role = message["role"]
                avatar = "👤" if role == "user" else "🤖"
                with st.chat_message(role, avatar=avatar):
                    st.markdown(message["content"])
        else:
            st.info("💡 Start a conversation by asking a question or clicking an example on the right!")

        st.markdown("---")

        # Custom query input stays at the bottom
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
                    st.session_state.chat_history.append({
                        'role': 'user',
                        'content': user_query,
                        'timestamp': datetime.now()
                    })
                    process_ai_query(user_query)
                    st.rerun()

        with col_clear:
            if st.button("🧹 Clear Chat", key="clear_chat"):
                st.session_state.chat_history = []
                st.rerun()

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
                    'model': 'phi3:mini'
                }
        except:
            continue

    return {'available': False}

def query_ollama(prompt: str, context: dict = None) -> str:
    """Query Ollama with improved prompt engineering"""
    ollama_status = check_ollama_connection()

    if not ollama_status['available']:
        return None

    try:
        log_context = build_log_context_for_query(prompt)

        # More specific and directive prompt
        full_prompt = f"""You are a cybersecurity analyst. Analyze the provided logs carefully and answer the user's question directly and accurately.

IMPORTANT INSTRUCTIONS:
1. Look at the actual log entries provided below
2. Answer based ONLY on what you see in the logs
3. If you see relevant information, report it specifically with timestamps and details
4. If no relevant logs exist, clearly state that
5. Be concise but include key details like dates, systems affected, and error messages

USER QUESTION: {prompt}

LOG DATA:
{log_context}

ANALYSIS:"""

        response = requests.post(
            f"{ollama_status['url']}/api/generate",
            json={
                "model": "phi3:mini",
                "prompt": full_prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,  # Lower temperature for more factual responses
                    "top_p": 0.8,
                    "max_tokens": 400,
                    "stop": ["USER QUESTION:", "LOG DATA:"]
                }
            },
            timeout=(10, 90)
        )

        if response.status_code == 200:
            result = response.json()
            ai_response = result.get('response', '').strip()
            return ai_response if ai_response else None
        else:
            print(f"Ollama API error: {response.status_code}")
            return None

    except requests.exceptions.ReadTimeout:
        print("Ollama read timeout after 90 seconds")
        return None
    except Exception as e:
        print(f"Ollama query error: {e}")
        return None

def build_log_context_for_query(query: str) -> str:
    """Build comprehensive and accurate log context - FIXED VERSION"""
    
    if not st.session_state.logs:
        return "No log data available."
    
    query_lower = query.lower()
    
    # Apply time filtering first if present
    time_filter = extract_time_reference(query_lower)
    if time_filter:
        filtered_logs = [log for log in st.session_state.logs
                        if log.timestamp >= time_filter['start'] and log.timestamp <= time_filter['end']]
        time_context = f"TIME PERIOD: {time_filter['description']}\n"
    else:
        filtered_logs = st.session_state.logs
        time_context = "TIME PERIOD: All available data\n"
    
    # Build comprehensive context without aggressive filtering
    context = time_context
    context += f"TOTAL LOGS: {len(filtered_logs)}\n\n"
    
    # Identify query intent and get relevant logs
    relevant_logs = get_relevant_logs_comprehensive(filtered_logs, query_lower)
    
    # Build detailed log entries
    context += build_detailed_log_entries(relevant_logs, query_lower)
    
    # Add anomaly information
    context += build_anomaly_context_comprehensive(query_lower)
    
    return context

def get_relevant_logs_comprehensive(logs: list, query: str) -> list:
    """Get relevant logs using comprehensive matching - no aggressive filtering"""
    
    # Keywords for different log types
    backup_keywords = ['backup', 'restore', 'vault']
    auth_keywords = ['login', 'auth', 'authentication', 'credential', 'user']
    error_keywords = ['error', 'fail', 'critical', 'exception', 'timeout']
    network_keywords = ['network', 'connection', 'timeout', 'unreachable']
    database_keywords = ['database', 'db', 'sql', 'query', 'connection']
    
    relevant_logs = []
    
    # Check what the query is asking about
    if any(keyword in query for keyword in backup_keywords):
        # For backup queries, include ALL backup-related logs
        relevant_logs = [log for log in logs if any(keyword in log.message.lower() 
                        for keyword in backup_keywords)]
    
    elif any(keyword in query for keyword in auth_keywords):
        # For auth queries, include ALL authentication logs
        relevant_logs = [log for log in logs if any(keyword in log.message.lower() 
                        for keyword in auth_keywords) or log.source == 'auth']
    
    elif any(keyword in query for keyword in error_keywords):
        # For error queries, include ALL error logs
        relevant_logs = [log for log in logs if log.level in ['ERROR', 'CRITICAL', 'FATAL']]
    
    elif any(keyword in query for keyword in network_keywords):
        # For network queries
        relevant_logs = [log for log in logs if any(keyword in log.message.lower() 
                        for keyword in network_keywords)]
    
    elif any(keyword in query for keyword in database_keywords):
        # For database queries
        relevant_logs = [log for log in logs if any(keyword in log.message.lower() 
                        for keyword in database_keywords)]
    
    else:
        # For general queries, prioritize recent errors and warnings
        relevant_logs = [log for log in logs if log.level in ['ERROR', 'CRITICAL', 'WARN']]
        if not relevant_logs:  # If no errors, show recent logs
            relevant_logs = sorted(logs, key=lambda x: x.timestamp, reverse=True)[:20]
    
    # Always sort by timestamp, most recent first
    return sorted(relevant_logs, key=lambda x: x.timestamp, reverse=True)

def build_detailed_log_entries(logs: list, query: str) -> str:
    """Build detailed log entries with full context"""
    
    if not logs:
        return "NO RELEVANT LOGS FOUND\n\n"
    
    context = f"RELEVANT LOG ENTRIES ({len(logs)} total):\n"
    
    # Show more logs for better context (up to 15 instead of 5)
    for i, log in enumerate(logs[:15]):
        context += f"[{log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {log.level} {log.source}: {log.message}\n"
    
    if len(logs) > 15:
        context += f"... and {len(logs) - 15} more similar entries\n"
    
    context += "\n"
    
    # Add summary statistics
    level_counts = {}
    for log in logs:
        level_counts[log.level] = level_counts.get(log.level, 0) + 1
    
    if level_counts:
        context += "LOG LEVEL SUMMARY:\n"
        for level in ['CRITICAL', 'ERROR', 'WARN', 'INFO']:
            count = level_counts.get(level, 0)
            if count > 0:
                context += f"- {level}: {count}\n"
        context += "\n"
    
    return context

def build_anomaly_context_comprehensive(query: str) -> str:
    """Build comprehensive anomaly context"""
    
    if not st.session_state.anomalies:
        return "DETECTED ANOMALIES: None\n"
    
    context = f"DETECTED ANOMALIES ({len(st.session_state.anomalies)} total):\n"
    
    for anomaly in st.session_state.anomalies:
        context += f"- {anomaly.type} ({anomaly.severity}): {anomaly.count} events, "
        context += f"{anomaly.confidence:.1%} confidence\n"
        context += f"  Description: {anomaly.description}\n"
        context += f"  Timeline: {anomaly.first_seen.strftime('%Y-%m-%d %H:%M')} to {anomaly.last_seen.strftime('%Y-%m-%d %H:%M')}\n"
    
    context += "\n"
    return context

def extract_time_reference(query: str) -> dict:
    """Extract time references from user query - ENHANCED VERSION"""
    import re
    
    now = datetime.now()
    query_lower = query.lower()

    # Specific day references
    if 'yesterday' in query_lower:
        start = now - timedelta(days=1)
        start = start.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)
        return {'start': start, 'end': end, 'description': 'Yesterday'}

    elif 'today' in query_lower:
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end = now
        return {'start': start, 'end': end, 'description': 'Today'}

    # Week references
    elif any(phrase in query_lower for phrase in ['last week', 'past week', 'previous week']):
        start = now - timedelta(days=7)
        return {'start': start, 'end': now, 'description': 'Last week'}

    elif 'this week' in query_lower:
        days_since_monday = now.weekday()
        start = now - timedelta(days=days_since_monday)
        start = start.replace(hour=0, minute=0, second=0, microsecond=0)
        return {'start': start, 'end': now, 'description': 'This week'}

    # Enhanced pattern matching for days
    day_patterns = [
        r'(?:last|past|previous|within|over the last|in the last|in the past|during the last)\s+(\d+)\s+days?',
        r'(\d+)\s+days?\s+ago',
        r'last\s+(\d+)d',  # shorthand like "last 5d"
    ]
    
    for pattern in day_patterns:
        match = re.search(pattern, query_lower)
        if match:
            days = int(match.group(1))
            # Validate reasonable range
            if days > 365:
                days = 365  # Cap at 1 year
            elif days < 1:
                days = 1
                
            start = now - timedelta(days=days)
            return {'start': start, 'end': now, 'description': f'Last {days} days'}

    # Enhanced pattern matching for hours
    hour_patterns = [
        r'(?:last|past|previous|within|over the last|in the last)\s+(\d+)\s+hours?',
        r'(\d+)\s+hours?\s+ago',
        r'last\s+(\d+)h',  # shorthand like "last 24h"
    ]
    
    for pattern in hour_patterns:
        match = re.search(pattern, query_lower)
        if match:
            hours = int(match.group(1))
            # Validate reasonable range
            if hours > 8760:  # 1 year in hours
                hours = 8760
            elif hours < 1:
                hours = 1
                
            start = now - timedelta(hours=hours)
            return {'start': start, 'end': now, 'description': f'Last {hours} hours'}

    # Special cases
    if 'last 24 hours' in query_lower or 'last day' in query_lower:
        start = now - timedelta(hours=24)
        return {'start': start, 'end': now, 'description': 'Last 24 hours'}

    # Month patterns
    month_patterns = [
        r'(?:last|past|previous)\s+(\d+)\s+months?',
        r'(\d+)\s+months?\s+ago',
    ]
    
    for pattern in month_patterns:
        match = re.search(pattern, query_lower)
        if match:
            months = int(match.group(1))
            if months > 12:
                months = 12
            elif months < 1:
                months = 1
                
            start = now - timedelta(days=months * 30)  # Approximate
            return {'start': start, 'end': now, 'description': f'Last {months} months'}

    return None

def filter_logs_by_subject(logs: list, query: str) -> list:
    """Filter logs based on query subject"""

    relevant_logs = []

    # Subject keywords mapping
    if any(word in query for word in ['backup', 'restore']):
        relevant_logs = [log for log in logs if any(term in log.message.lower()
                        for term in ['backup', 'restore']) or 'backup' in log.source.lower()]

    elif any(word in query for word in ['login', 'auth', 'authentication']):
        relevant_logs = [log for log in logs if any(term in log.message.lower()
                        for term in ['login', 'auth', 'authentication']) or log.source == 'auth']

    elif any(word in query for word in ['vault', 'secret']):
        relevant_logs = [log for log in logs if any(term in log.message.lower()
                        for term in ['vault', 'secret']) or 'vault' in log.source.lower()]

    elif any(word in query for word in ['error', 'failure', 'issue']):
        relevant_logs = [log for log in logs if log.level in ['ERROR', 'CRITICAL', 'FATAL']]

    elif any(word in query for word in ['database', 'db', 'sql']):
        relevant_logs = [log for log in logs if any(term in log.message.lower()
                        for term in ['database', 'db', 'sql', 'query']) or 'database' in log.source.lower()]

    else:
        # If no specific subject, return all logs but prioritize errors and warnings
        relevant_logs = logs

    return relevant_logs

def process_ai_query(query: str, debug: bool = True):
    """Enhanced AI query processing with better fallback - FIXED VERSION"""

    # First try to get response from Ollama Phi-3 Mini
    llm_response = query_ollama(query, {'anomalies': st.session_state.anomalies})

    if debug:
        print("🔎 process_ai_query DEBUG")
        print("  • User query:", query)
        print("  • LLM raw response:", repr(llm_response))
        print("  • Fallback triggered?:", llm_response is None)

    if llm_response is not None and len(llm_response.strip()) > 10:
        response = f"**🤖 AI Analysis (Phi-3 Mini):**\n\n{llm_response}"
    else:
        response = f"**🤖 Built-in Analysis:**\n\n{generate_intelligent_response(query)}"

        # Add note about LLM status
        ollama_status = check_ollama_connection()
        if not ollama_status['available']:
            response += "\n\n*Note: Advanced AI (Phi-3 Mini) is not available. Using built-in analysis.*"
        else:
            response += "\n\n*Note: AI model response was insufficient. Using enhanced built-in analysis.*"

    # Add to chat history
    st.session_state.chat_history.append({
        'role': 'assistant',
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
    """Generate response about suspicious activities - FIXED VERSION"""

    if not st.session_state.anomalies:
        return "📊 **Suspicious Activities Analysis:**\n\nNo suspicious activities detected in the current analysis."

    # Sort anomalies by severity and confidence
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
        response += f"   • **Timeline:** {anomaly.first_seen.strftime('%Y-%m-%d %H:%M')} - {anomaly.last_seen.strftime('%Y-%m-%d %H:%M')}\n"
        response += f"   • **Details:** {anomaly.description}\n"

        # Add affected resources if available
        if hasattr(anomaly, 'affected_resources') and anomaly.affected_resources:
            resources_str = ", ".join(anomaly.affected_resources[:3])
            if len(anomaly.affected_resources) > 3:
                resources_str += f" (and {len(anomaly.affected_resources)-3} more)"
            response += f"   • **Affected Resources:** {resources_str}\n"

        response += "\n"

    # Add context from actual logs
    response += "**Additional Context from Logs:**\n"

    # Find recent critical/error logs
    critical_logs = [log for log in st.session_state.logs
                    if log.level in ['CRITICAL', 'ERROR', 'FATAL']
                    and (datetime.now() - log.timestamp).days <= 1]

    if critical_logs:
        response += f"• {len(critical_logs)} critical/error events in last 24 hours\n"
        # Show most recent critical event
        recent_critical = sorted(critical_logs, key=lambda x: x.timestamp, reverse=True)[0]
        response += f"• Most recent: {recent_critical.timestamp.strftime('%Y-%m-%d %H:%M')} - {recent_critical.message[:60]}...\n"

    response += "\n💡 **Recommendation:** Prioritize investigation of high-severity issues and implement additional monitoring."

    return response

def generate_vault_response() -> str:
    """Generate response about vault/backup issues - COMPREHENSIVE VERSION"""
    
    # Get time filter if present
    time_filter = extract_time_reference("last 3 days")
    
    if time_filter:
        filtered_logs = [log for log in st.session_state.logs
                        if log.timestamp >= time_filter['start'] and log.timestamp <= time_filter['end']]
        time_desc = time_filter['description']
    else:
        filtered_logs = st.session_state.logs
        time_desc = "all available data"

    # Find ALL backup-related logs
    backup_logs = [log for log in filtered_logs if 'backup' in log.message.lower()]
    
    # Separate failures and successes
    backup_failures = [log for log in backup_logs 
                      if log.level in ['ERROR', 'CRITICAL'] or 'failed' in log.message.lower()]
    backup_successes = [log for log in backup_logs 
                       if 'completed successfully' in log.message.lower()]

    response = f"**Vault/Backup Analysis ({time_desc}):**\n\n"
    
    if not backup_logs:
        response += "No backup-related logs found in the specified time period."
        return response
    
    response += f"**Summary:**\n"
    response += f"- Total backup operations: {len(backup_logs)}\n"
    response += f"- Failed backups: {len(backup_failures)}\n"
    response += f"- Successful backups: {len(backup_successes)}\n\n"
    
    if backup_failures:
        response += f"**Backup Failures ({len(backup_failures)}):**\n"
        for failure in sorted(backup_failures, key=lambda x: x.timestamp, reverse=True):
            response += f"- {failure.timestamp.strftime('%Y-%m-%d %H:%M')} | {failure.source} | {failure.message}\n"
        response += "\n"
    
    if backup_successes:
        response += f"**Recent Successful Backups:**\n"
        for success in sorted(backup_successes, key=lambda x: x.timestamp, reverse=True)[:3]:
            response += f"- {success.timestamp.strftime('%Y-%m-%d %H:%M')} | {success.source} | {success.message}\n"
    
    return response

def generate_auth_response() -> str:
    """Generate response about authentication issues - FIXED VERSION"""

    # Actually analyze the loaded log data
    auth_logs = []
    failed_logins = []

    # Check actual log messages for authentication events
    for log in st.session_state.logs:
        message_lower = log.message.lower()

        # Look for authentication events
        if any(term in message_lower for term in ['login', 'auth', 'authentication']):
            auth_logs.append(log)

            # Check if it's a failure
            if any(term in message_lower for term in ['failed', 'denied', 'invalid', 'error']):
                failed_logins.append(log)

    # Check anomalies for auth-related issues
    auth_anomalies = [a for a in st.session_state.anomalies
                     if any(term in a.type.lower() for term in ['login', 'auth', 'access'])]

    response = "🔐 **Authentication Security Analysis:**\n\n"

    if not auth_logs and not auth_anomalies:
        response += "No authentication logs found in the analyzed data."
        return response

    # Summary statistics
    response += f"• **Total authentication events:** {len(auth_logs)}\n"
    response += f"• **Failed attempts:** {len(failed_logins)}\n"

    if len(auth_logs) > 0:
        success_rate = ((len(auth_logs) - len(failed_logins)) / len(auth_logs)) * 100
        response += f"• **Success rate:** {success_rate:.1f}%\n"

    response += "\n"

    if failed_logins:
        # Analyze failed logins by IP
        failed_by_ip = {}
        for log in failed_logins:
            ip = getattr(log, 'ip_address', None) or "unknown"
            failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1

        # Show top failing IPs
        if failed_by_ip and any(ip != "unknown" for ip in failed_by_ip.keys()):
            response += "**Failed Logins by IP:**\n"
            sorted_ips = sorted(failed_by_ip.items(), key=lambda x: x[1], reverse=True)
            for ip, count in sorted_ips[:5]:
                response += f"• {ip}: {count} failed attempts\n"
            response += "\n"

        # Show recent failures
        recent_failures = sorted(failed_logins, key=lambda x: x.timestamp, reverse=True)[:5]
        response += "**Recent Failed Attempts:**\n"
        for log in recent_failures:
            response += f"• {log.timestamp.strftime('%Y-%m-%d %H:%M')} - {log.message[:80]}...\n"
        response += "\n"

    # Show authentication anomalies
    if auth_anomalies:
        response += f"**Security Anomalies:** {len(auth_anomalies)} detected\n\n"
        for anomaly in auth_anomalies:
            response += f"🚨 **{anomaly.type}** (Severity: {anomaly.severity})\n"
            response += f"   Count: {anomaly.count}, Confidence: {anomaly.confidence:.1%}\n"
            response += f"   Description: {anomaly.description}\n\n"

        # Check for potential brute force
        brute_force = [a for a in auth_anomalies if a.count >= 10]
        if brute_force:
            response += "⚠️ **Potential brute force attacks detected!**\n\n"

    if failed_logins or auth_anomalies:
        response += "💡 **Immediate Actions:**\n"
        response += "• Review failed authentication sources\n"
        response += "• Implement account lockout policies\n"
        response += "• Consider IP-based blocking for repeat offenders\n"
    else:
        response += "✅ **Status:** No significant authentication issues detected.\n"

    return response

def generate_summary_response() -> str:
    """Generate general summary response - FIXED VERSION"""

    total_logs = len(st.session_state.logs)
    total_anomalies = len(st.session_state.anomalies)
    risk_level = st.session_state.summary.get('overall_risk', 'UNKNOWN')

    risk_emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(risk_level, "⚪")

    response = f"📊 **Security Analysis Summary:**\n\n"
    response += f"• **Data Analyzed:** {total_logs:,} log entries\n"
    response += f"• **Anomalies Found:** {total_anomalies}\n"
    response += f"• **Risk Assessment:** {risk_level} {risk_emoji}\n\n"

    if st.session_state.logs:
        # Time range analysis
        timestamps = [log.timestamp for log in st.session_state.logs]
        time_range = max(timestamps) - min(timestamps)
        response += f"**Analysis Period:** {time_range.days} days of log data\n"
        response += f"**Data Range:** {min(timestamps).strftime('%Y-%m-%d')} to {max(timestamps).strftime('%Y-%m-%d')}\n\n"

        # Log level distribution
        level_counts = {}
        for log in st.session_state.logs:
            level_counts[log.level] = level_counts.get(log.level, 0) + 1

        response += "**Log Levels Distribution:**\n"
        for level in ['CRITICAL', 'ERROR', 'WARN', 'INFO', 'DEBUG']:
            count = level_counts.get(level, 0)
            if count > 0:
                percentage = (count / total_logs) * 100
                emoji = {"CRITICAL": "🔴", "ERROR": "🟠", "WARN": "🟡", "INFO": "🔵", "DEBUG": "⚫"}.get(level, "⚪")
                response += f"• {level}: {count} ({percentage:.1f}%) {emoji}\n"

        response += "\n"

        # Source analysis
        source_counts = {}
        for log in st.session_state.logs:
            source_counts[log.source] = source_counts.get(log.source, 0) + 1

        response += "**Top Log Sources:**\n"
        sorted_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        for source, count in sorted_sources:
            response += f"• {source}: {count} entries\n"

    if st.session_state.anomalies:
        response += "\n**Security Issues by Severity:**\n"
        severity_counts = {}
        for anomaly in st.session_state.anomalies:
            severity_counts[anomaly.severity] = severity_counts.get(anomaly.severity, 0) + 1

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[severity]
                response += f"• {severity}: {count} {emoji}\n"

        response += "\n**Top Issue Types:**\n"
        anomaly_types = {}
        for anomaly in st.session_state.anomalies:
            anomaly_types[anomaly.type] = anomaly_types.get(anomaly.type, 0) + 1

        sorted_types = sorted(anomaly_types.items(), key=lambda x: x[1], reverse=True)[:3]
        for anomaly_type, count in sorted_types:
            response += f"• {anomaly_type}: {count} incidents\n"
    else:
        response += "\n✅ **Good News:** No security anomalies detected!\n"

    return response

def generate_pattern_response() -> str:
    """Generate response about access patterns"""
    response = "🔍 **Access Pattern Analysis:**\n\n"

    if not st.session_state.logs:
        return response + "No log data available for pattern analysis."

    # Analyze IP patterns
    ip_addresses = [getattr(log, 'ip_address', None) for log in st.session_state.logs]
    ip_addresses = [ip for ip in ip_addresses if ip]  # Remove None values

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
- Log entries processed: {len(st.session_state.logs):,}
- Security anomalies detected: {len(st.session_state.anomalies)}
- Risk level: {st.session_state.summary.get('overall_risk', 'Unknown')}

**🎯 What you can ask me:**
- **"Top suspicious activities"** - Get prioritized security threats
- **"Authentication issues"** - Review login failures and access problems
- **"Backup system status"** - Check backup and restore operations
- **"Access patterns"** - Analyze user and IP behavior
- **"System health summary"** - Overall security posture

**💡 Pro tip:** Be specific! Ask things like "Show me failed logins from external IPs" or "What backup failures happened this week?"

What specific aspect of your security logs would you like me to analyze?"""


if __name__ == "__main__":
    main()
