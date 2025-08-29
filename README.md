# 🔒 AI-Augmented Log Analysis System

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-supported-blue.svg)](https://docker.com/)
[![Streamlit](https://img.shields.io/badge/streamlit-1.28+-red.svg)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🎯 Project Overview

An intelligent log analysis system that ingests system/application logs, detects security anomalies using AI, and generates natural language summaries for rapid threat response. Built for hackathons with enterprise-grade features.

### ✨ Key Features

- 🤖 **AI-Powered Anomaly Detection** - Multiple ML algorithms for pattern recognition
- 📊 **Interactive Web Dashboard** - Built with Streamlit for real-time analysis
- 🧠 **Natural Language Summaries** - Integration with Ollama LLaMA2 for AI-generated insights
- 📈 **Grafana Visualization** - Professional monitoring dashboards
- 📑 **PowerPoint Reporting** - Automated executive summary generation
- 🐳 **Full Docker Support** - One-command deployment with Docker Compose
- 🔍 **Multi-Log Format Support** - Apache, Nginx, Syslog, Security, Backup, Vault logs

## 🚀 Quick Start

### Option 1: Automated Setup (Recommended)
```bash
# Clone or download the project files
# Run the automated setup script
chmod +x setup.sh
./setup.sh

# Start the application
./run_docker.sh  # Full Docker environment
# OR
./run_dev.sh     # Development mode
```

### Option 2: Manual Setup
```bash
# 1. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate     # Windows

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate sample data
python sample_log_generator.py

# 4. Start the application
streamlit run streamlit_app.py
```

## 🏗️ System Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Log Sources   │───▶│  Log Analyzer    │───▶│   Web UI        │
│  • Security     │    │  • Pattern Match │    │  • Streamlit    │
│  • Backup       │    │  • ML Clustering │    │  • Dashboards   │
│  • Vault        │    │  • Anomaly Det.  │    │  • Reports      │
│  • System       │    │  • AI Summary    │    │  • Alerts       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌──────────────────┐            │
         │              │     Ollama       │            │
         │              │   LLaMA2 Model   │            │
         │              └──────────────────┘            │
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 ▼
                    ┌──────────────────────┐
                    │    Monitoring        │
                    │  • Grafana          │
                    │  • Prometheus       │
                    │  • Metrics          │
                    └──────────────────────┘
```

## 📁 Project Structure

```
ai-log-analyzer/
├── 📄 log_analyzer.py          # Core analysis engine
├── 🌐 streamlit_app.py         # Web interface
├── 📊 ppt_generator.py         # PowerPoint report generator
├── 🔧 sample_log_generator.py  # Sample data generator
├── 🐳 Dockerfile               # Container configuration
├── 🐳 docker-compose.yml       # Multi-service orchestration
├── 📋 requirements.txt         # Python dependencies
├── ⚙️ setup.sh                # Automated setup script
├── 🚀 run_docker.sh           # Docker startup script
├── 🚀 run_dev.sh              # Development startup script
├── 🛑 stop_services.sh        # Service shutdown script
├── 📁 logs/                   # Log file directory
│   ├── security.log           # Sample security logs
│   ├── backup.log             # Sample backup logs
│   ├── vault.log              # Sample vault logs
│   ├── system.log             # Sample system logs
│   └── apache_access.log      # Sample web server logs
├── 📁 grafana/                # Grafana configuration
│   ├── dashboards/            # Dashboard definitions
│   └── datasources/           # Data source configs
├── 📁 prometheus/             # Prometheus configuration
└── 📁 reports/                # Generated reports
```

## 🔍 Anomaly Detection Capabilities

### Supported Log Formats
- **Apache/Nginx** - Web server access logs
- **Syslog** - System event logs
- **Security Logs** - Authentication and access logs
- **Backup Logs** - Backup system status
- **Vault Logs** - Secret management logs
- **Custom Formats** - Extensible parser framework

### Detection Algorithms
1. **Failed Login Detection** - Brute force attack identification
2. **Error Spike Analysis** - System health anomaly detection
3. **Access Pattern Analysis** - Unusual user behavior detection
4. **Time-based Anomalies** - Off-hours activity monitoring
5. **IP Reputation Analysis** - Suspicious source identification
6. **Backup Failure Detection** - Critical system monitoring

## 🌐 Web Interface Features

### Dashboard Components
- **📊 Real-time Metrics** - Live anomaly counts and risk levels
- **📈 Interactive Charts** - Plotly-powered visualizations
- **🔍 Detailed Analysis** - Drill-down capabilities
- **📑 Export Options** - JSON, PowerPoint, Email alerts
- **🤖 AI Summaries** - Natural language threat descriptions

### Supported Visualizations
- Anomaly timeline scatter plots
- Log level distribution pie charts
- Hourly activity patterns
- Top IP address analysis
- Risk assessment matrices

## 🤖 AI Integration

### Ollama LLaMA2 Integration
- **Local AI Processing** - No external API dependencies
- **Custom Prompts** - Tailored security analysis
- **Multi-model Support** - LLaMA2, CodeLLaMA, Mistral
- **Fallback Mode** - Built-in summarizer if AI unavailable

### AI-Generated Content
- Executive security summaries
- Threat landscape analysis
- Risk assessment narratives
- Actionable recommendation lists

## 📊 Monitoring & Visualization

### Grafana Dashboards
- **Security Overview** - High-level threat metrics
- **Anomaly Trends** - Historical pattern analysis
- **System Health** - Log processing statistics
- **Alert Status** - Real-time notification panel

### Prometheus Metrics
- Log processing rates
- Anomaly detection counts
- System performance metrics
- Alert generation statistics

## 📑 Reporting Features

### PowerPoint Generation
- **Executive Summary** - C-level appropriate content
- **Technical Details** - Detailed findings for security teams
- **Visual Charts** - Embedded graphs and timelines
- **Action Items** - Prioritized recommendation lists

### Export Options
- **JSON Reports** - Machine-readable format
- **Email Alerts** - Template-based notifications
- **PDF Summaries** - Printer-friendly reports
- **CSV Data** - Raw data for further analysis

## 🐳 Docker Deployment

### Services Included
- **log-analyzer** - Main Streamlit application
- **ollama** - Local LLaMA model server
- **grafana** - Visualization dashboard
- **prometheus** - Metrics collection

### Quick Deployment
```bash
# Start all services
./run_docker.sh

# Access applications
# Web UI: http://localhost:8501
# Grafana: http://localhost:3000 (admin/admin123)
# Prometheus: http://localhost:9090
```

## ⚙️ Configuration

### Environment Variables
```bash
# Ollama Configuration
OLLAMA_HOST=localhost:11434
OLLAMA_MODEL=llama2

# Analysis Settings
FAILED_LOGIN_THRESHOLD=10
ERROR_SPIKE_THRESHOLD=5
CONFIDENCE_THRESHOLD=0.8

# Monitoring
GRAFANA_ADMIN_PASSWORD=admin123
PROMETHEUS_RETENTION=7d
```

### Log Parser Configuration
Customize detection patterns in `log_analyzer.py`:
```python
self.patterns = {
    'custom_format': r'(?P<timestamp>...) (?P<level>...) (?P<message>...)',
    # Add your custom patterns here
}
```

## 📈 Performance & Scalability

### System Requirements
- **Minimum**: 4GB RAM, 2 CPU cores
- **Recommended**: 8GB RAM, 4 CPU cores
- **Storage**: 10GB free space (for models and logs)

### Processing Capacity
- **Log Volume**: Up to 1M entries per analysis
- **Real-time**: Processing 1000s logs/second
- **Response Time**: < 5 seconds for analysis
- **Concurrent Users**: Up to 10 simultaneous sessions

## 🔒 Security Considerations

### Data Privacy
- **Local Processing** - No data leaves your environment
- **Anonymization** - Built-in data sanitization
- **Access Control** - Configurable authentication
- **Audit Trail** - All actions logged

### Security Features
- Input validation and sanitization
- SQL injection prevention
- XSS protection in web interface
- Secure Docker container configuration

## 🧪 Testing & Validation

### Sample Data Generation
```bash
python sample_log_generator.py
```
Generates realistic anonymized logs for testing:
- 1000+ security events
- Multiple attack scenarios
- Various log formats
- Realistic timestamps and IPs

### Validation Scenarios
- ✅ Failed login attack detection
- ✅ Error spike identification
- ✅ Off-hours activity monitoring
- ✅ Suspicious IP behavior
- ✅ Backup failure alerting

## 🚨 Troubleshooting

### Common Issues

#### Docker Issues
```bash
# Docker not starting
sudo systemctl start docker

# Permission denied
sudo usermod -aG docker $USER
# Logout and login again
```

#### Ollama Model Issues
```bash
# Download model manually
docker exec -it ollama ollama pull llama2

# Check model status
docker exec -it ollama ollama list
```

#### Streamlit Issues
```bash
# Port already in use
lsof -ti:8501 | xargs kill -9

# Clear cache
streamlit cache clear
```

#### Memory Issues
```bash
# Monitor usage
docker stats

# Increase Docker memory limit
# Docker Desktop > Settings > Resources > Memory
```

### Log Analysis Issues
- **No anomalies detected**: Check log format compatibility
- **False positives**: Adjust detection thresholds
- **Missing timestamps**: Verify log parser patterns
- **Performance issues**: Reduce log file size for testing

## 🎯 Hackathon Deployment Guide

### 5-Minute Demo Setup
```bash
# 1. Download project files
# 2. Run automated setup
chmod +x setup.sh && ./setup.sh

# 3. Start demo environment  
./run_docker.sh

# 4. Access demo at http://localhost:8501
# 5. Click "Use Sample Data" for instant demo
```

### Presentation Points
1. **Real-time Detection** - Live anomaly identification
2. **AI Summaries** - Natural language insights
3. **Executive Reporting** - Automated PowerPoint generation
4. **Multi-format Support** - Various log types
5. **Scalable Architecture** - Production-ready deployment

### Demo Scenarios
1. **Security Breach** - Failed login attack detection
2. **System Issues** - Backup failure identification  
3. **Threat Intelligence** - AI-generated analysis
4. **Executive Summary** - PowerPoint report generation

## 🛠️ Customization Guide

### Adding New Log Formats
```python
# In log_analyzer.py, add to patterns dictionary
'new_format': r'(?P<timestamp>...) (?P<level>...) (?P<message>...)'
```

### Custom Anomaly Detection
```python
def detect_custom_anomaly(self, df):
    # Implement your detection logic
    anomalies = []
    # ... detection code ...
    return anomalies
```

### UI Customization
```python
# In streamlit_app.py, modify layout
st.set_page_config(
    page_title="Custom Title",
    page_icon="🔒",
    layout="wide"
)
```

## 📚 API Reference

### Core Classes

#### `LogParser`
```python
parser = LogParser()
entries = parser.parse_log_file("path/to/log")
```

#### `AnomalyDetector`
```python
detector = AnomalyDetector()
anomalies = detector.detect_anomalies(log_entries)
```

#### `ThreatSummarizer`
```python
summarizer = ThreatSummarizer()
summary = summarizer.generate_summary(anomalies)
```

## 🤝 Contributing

### Development Setup
```bash
# Clone repository
git clone <repository-url>
cd ai-log-analyzer

# Create development environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Install development dependencies
pip install pytest black flake8 mypy
```

### Code Quality
```bash
# Format code
black *.py

# Lint code
flake8 *.py

# Type checking
mypy *.py

# Run tests
pytest
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🎉 Acknowledgments

- **Streamlit** - Web application framework
- **Ollama** - Local AI model deployment
- **Grafana** - Visualization platform
- **scikit-learn** - Machine learning algorithms
- **Plotly** - Interactive charts

## 📞 Support & Contact

For hackathon support or questions:
- 📧 Email: [your-email@example.com]
- 💬 Discord: [your-discord-handle]
- 🐛 Issues: [GitHub Issues URL]

---

**Built with ❤️ for security professionals and hackathon enthusiasts!**

