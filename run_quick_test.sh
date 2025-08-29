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
