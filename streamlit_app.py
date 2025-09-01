import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
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

        # --- Move Example Queries above Capabilities ---
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
                    # New Line below
                    # Clear the text area
                    st.session_state.user_query_input = ""
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
                    'model': 'llama2'  # Default model
                }
        except:
            continue

    return {'available': False}

def query_ollama(prompt: str, context: dict = None) -> str:
    """Query Ollama Phi-3 Mini with proper context and data analysis"""
    ollama_status = check_ollama_connection()
    
    if not ollama_status['available']:
        return None  # Return None to trigger fallback
    
    try:
        # Build context from log data
        log_context = build_log_context_for_query(prompt)
        
        # Create structured prompt
        full_prompt = f"""You are a cybersecurity analyst.
Analyze the logs below and answer the user's question.

Rules:
1. Always reference timestamps, counts, or anomaly details if relevant.
2. If no relevant information exists in the logs, respond with: "No matching logs found."
3. Keep the answer concise but specific (2–5 sentences).
4. Do not give generic responses.

User Question:
{prompt}

LOG CONTEXT:
{log_context}

Answer:"""

        # Query Phi-3 Mini
        response = requests.post(
            f"{ollama_status['url']}/api/generate",
            json={
                "model": "phi3:mini",
                "prompt": full_prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2,   # Slightly higher for variety but still factual
                    "top_p": 0.9,
                    "max_tokens": 400,
                    "stop": ["Answer:"]
                }
            },
            timeout=60
        )
        
        if response.status_code == 200:
            result = response.json()
            ai_response = result.get('response', '').strip()
            
            # Debugging — see raw output in logs
            print("RAW LLM RESPONSE:", ai_response)
            
            # Clean up and accept shorter answers as long as they aren't empty
            if not ai_response or ai_response.lower() in ["none", "no data"]:
                return "No matching logs found."
            
            return ai_response
        else:
            print(f"Ollama API error: {response.status_code}, {response.text}")
            return None
            
    except Exception as e:
        print(f"Ollama query error: {e}")
        return None

def build_log_context_for_query(query: str) -> str:
    """Build relevant log context based on the user's query"""
    
    if not st.session_state.logs:
        return "No log data available."
    
    query_lower = query.lower()
    
    # Extract time references from query
    time_filter = extract_time_reference(query_lower)
    
    # Filter logs based on time reference
    if time_filter:
        relevant_logs = [log for log in st.session_state.logs 
                        if log.timestamp >= time_filter['start'] and log.timestamp <= time_filter['end']]
        time_context = f"TIME PERIOD: {time_filter['description']}\n"
    else:
        relevant_logs = st.session_state.logs
        time_context = "TIME PERIOD: All available data\n"
    
    # Filter logs by relevance to query
    subject_logs = filter_logs_by_subject(relevant_logs, query_lower)
    
    # Build context string
    context = time_context
    context += f"TOTAL LOGS IN PERIOD: {len(relevant_logs)}\n"
    context += f"RELEVANT LOGS: {len(subject_logs)}\n\n"
    
    # Add summary statistics
    if subject_logs:
        context += build_log_statistics(subject_logs, query_lower)
    
    # Add recent specific log entries
    context += build_specific_log_entries(subject_logs, query_lower)
    
    # Add anomaly information
    context += build_anomaly_context(query_lower, time_filter)
    
    return context

def extract_time_reference(query: str) -> dict:
    """Extract time references from user query"""
    
    now = datetime.now()
    
    # Time patterns
    if 'yesterday' in query:
        start = now - timedelta(days=1)
        start = start.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)
        return {'start': start, 'end': end, 'description': 'Yesterday'}
    
    elif 'today' in query:
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end = now
        return {'start': start, 'end': end, 'description': 'Today'}
    
    elif 'last 24 hours' in query or 'last day' in query:
        start = now - timedelta(hours=24)
        return {'start': start, 'end': now, 'description': 'Last 24 hours'}
    
    elif 'last 3 days' in query:
        start = now - timedelta(days=3)
        return {'start': start, 'end': now, 'description': 'Last 3 days'}
    
    elif 'last week' in query or 'past week' in query:
        start = now - timedelta(days=7)
        return {'start': start, 'end': now, 'description': 'Last week'}
    
    elif 'this week' in query:
        # Start of current week (Monday)
        days_since_monday = now.weekday()
        start = now - timedelta(days=days_since_monday)
        start = start.replace(hour=0, minute=0, second=0, microsecond=0)
        return {'start': start, 'end': now, 'description': 'This week'}
    
    # Try to extract "last X days/hours"
    import re
    
    days_match = re.search(r'last (\d+) days?', query)
    if days_match:
        days = int(days_match.group(1))
        start = now - timedelta(days=days)
        return {'start': start, 'end': now, 'description': f'Last {days} days'}
    
    hours_match = re.search(r'last (\d+) hours?', query)
    if hours_match:
        hours = int(hours_match.group(1))
        start = now - timedelta(hours=hours)
        return {'start': start, 'end': now, 'description': f'Last {hours} hours'}
    
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

def build_log_statistics(logs: list, query: str) -> str:
    """Build statistics from filtered logs"""
    
    if not logs:
        return "NO RELEVANT LOGS FOUND\n\n"
    
    stats = "LOG STATISTICS:\n"
    
    # Count by level
    level_counts = {}
    for log in logs:
        level_counts[log.level] = level_counts.get(log.level, 0) + 1
    
    for level in ['CRITICAL', 'ERROR', 'WARN', 'INFO']:
        count = level_counts.get(level, 0)
        if count > 0:
            stats += f"- {level}: {count}\n"
    
    # Count by source
    source_counts = {}
    for log in logs:
        source_counts[log.source] = source_counts.get(log.source, 0) + 1
    
    stats += "\nBY SOURCE:\n"
    sorted_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)
    for source, count in sorted_sources[:5]:
        stats += f"- {source}: {count}\n"
    
    stats += "\n"
    return stats

def build_specific_log_entries(logs: list, query: str) -> str:
    """Build specific log entries relevant to the query"""
    
    if not logs:
        return ""
    
    context = "SPECIFIC LOG ENTRIES:\n"
    
    # Sort by timestamp, most recent first
    sorted_logs = sorted(logs, key=lambda x: x.timestamp, reverse=True)
    
    # Show up to 10 most relevant entries
    shown_count = 0
    for log in sorted_logs:
        if shown_count >= 10:
            break
            
        # Format log entry
        context += f"[{log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {log.level} | {log.source} | {log.message}\n"
        shown_count += 1
    
    if len(sorted_logs) > 10:
        context += f"... and {len(sorted_logs) - 10} more entries\n"
    
    context += "\n"
    return context

def build_anomaly_context(query: str, time_filter: dict) -> str:
    """Build context from detected anomalies"""
    
    if not st.session_state.anomalies:
        return "DETECTED ANOMALIES: None\n"
    
    # Filter anomalies by time if specified
    if time_filter:
        relevant_anomalies = [a for a in st.session_state.anomalies 
                            if a.first_seen >= time_filter['start'] and a.first_seen <= time_filter['end']]
    else:
        relevant_anomalies = st.session_state.anomalies
    
    if not relevant_anomalies:
        return f"DETECTED ANOMALIES: None in specified time period\n"
    
    context = f"DETECTED ANOMALIES ({len(relevant_anomalies)}):\n"
    
    for anomaly in relevant_anomalies:
        context += f"- {anomaly.type} ({anomaly.severity}): {anomaly.count} events, {anomaly.confidence:.1%} confidence\n"
        context += f"  Time: {anomaly.first_seen.strftime('%Y-%m-%d %H:%M')} to {anomaly.last_seen.strftime('%Y-%m-%d %H:%M')}\n"
        context += f"  Description: {anomaly.description}\n"
    
    context += "\n"
    return context


def process_ai_query(query: str, debug: bool = True):
    """Enhanced AI query processing using Ollama Phi-3 Mini"""
    
    # First try to get response from Ollama Phi-3 Mini
    llm_response = query_ollama(query, {'anomalies': st.session_state.anomalies})
    
    if debug:
        print("🔎 process_ai_query DEBUG")
        print("  • User query:", query)
        print("  • LLM raw response:", repr(llm_response))
        print("  • Fallback triggered?:", llm_response is None)
    
    if llm_response is not None:  # Only fallback when truly None
        response = f"**🤖 AI Analysis (Phi-3 Mini):**\n\n{llm_response}"
    else:
        response = f"**🤖 Built-in Analysis:**\n\n{generate_intelligent_response(query)}"
        
        # Add note about LLM status
        ollama_status = check_ollama_connection()
        if not ollama_status['available']:
            response += "\n\n*Note: Advanced AI (Phi-3 Mini) is not available. Using built-in analysis.*"
        else:
            response += "\n\n*Note: AI model provided insufficient response. Using enhanced built-in analysis.*"
    
    # ✅ Use 'role' instead of 'type'
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
        if anomaly.affected_resources:
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
    """Generate response about vault/backup issues - FIXED VERSION"""
    
    # Actually analyze the loaded log data
    backup_issues = []
    vault_issues = []
    
    # Check actual log messages for backup/vault failures
    for log in st.session_state.logs:
        message_lower = log.message.lower()
        
        # Look for backup failures
        if any(term in message_lower for term in ['backup failed', 'backup.*failed', 'backup.*error']):
            backup_issues.append(log)
        
        # Look for vault failures  
        if any(term in message_lower for term in ['vault', 'restore failed', 'restore.*failed']):
            vault_issues.append(log)
    
    # Also check anomalies for backup/vault related issues
    backup_anomalies = [a for a in st.session_state.anomalies 
                       if any(term in a.type.lower() or term in a.description.lower() 
                             for term in ['vault', 'backup', 'restore'])]
    
    if not backup_issues and not vault_issues and not backup_anomalies:
        return "🗄️ **Vault/Backup Analysis:**\n\nNo vault or backup failures detected in the analyzed logs. Your backup systems appear to be functioning properly."
    
    response = "🗄️ **Vault/Backup Analysis:**\n\n"
    
    # Report backup failures from logs
    if backup_issues:
        response += f"**Backup Failures Found:** {len(backup_issues)} incidents\n\n"
        
        # Group by time periods
        recent_failures = [log for log in backup_issues 
                          if (datetime.now() - log.timestamp).days <= 3]
        
        if recent_failures:
            response += f"**Last 3 Days:** {len(recent_failures)} backup failures\n"
            for log in recent_failures[-5:]:  # Show last 5
                response += f"• {log.timestamp.strftime('%Y-%m-%d %H:%M')} - {log.source}: {log.message[:80]}...\n"
        
        response += "\n"
    
    # Report vault issues
    if vault_issues:
        response += f"**Vault Issues Found:** {len(vault_issues)} incidents\n\n"
        for log in vault_issues[-3:]:  # Show last 3
            response += f"• {log.timestamp.strftime('%Y-%m-%d %H:%M')} - {log.message[:80]}...\n"
        response += "\n"
    
    # Report anomalies
    if backup_anomalies:
        response += f"**Detected Anomalies:** {len(backup_anomalies)} backup/vault anomalies\n\n"
        for anomaly in backup_anomalies:
            response += f"• **{anomaly.type}** ({anomaly.severity} severity)\n"
            response += f"  Count: {anomaly.count}, Confidence: {anomaly.confidence:.1%}\n"
            response += f"  Description: {anomaly.description}\n\n"
    
    response += "💡 **Recommendation:** Review backup procedures and ensure redundancy for critical systems."
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
            ip = log.ip_address or "unknown"
            failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1
        
        # Show top failing IPs
        if failed_by_ip:
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
