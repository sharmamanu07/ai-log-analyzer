#!/bin/bash

# Complete Docker Setup Script for AI Log Analysis with LLM Support
# This script sets up the entire system including LLM services

echo "🐳 AI Log Analysis System - Complete Docker Setup"
echo "================================================="

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check Docker availability
check_docker() {
    print_info "Checking Docker installation..."
    
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed!"
        echo "Please install Docker: https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running!"
        echo "Please start Docker and try again"
        exit 1
    fi
    
    print_status "Docker is available and running"
    
    # Check Docker Compose
    if command -v docker-compose &> /dev/null; then
        print_status "Docker Compose found"
    elif docker compose version &> /dev/null; then
        print_status "Docker Compose (plugin) found"
        alias docker-compose="docker compose"
    else
        print_error "Docker Compose not found!"
        echo "Please install Docker Compose"
        exit 1
    fi
}

# Create necessary files
create_project_files() {
    print_info "Creating project files..."
    
    # Ensure all required files exist
    required_files=(
        "log_analyzer.py"
        "docker_friendly_llm.py" 
        "updated_streamlit_docker.py"
        "requirements.txt"
        "docker-compose.yml"
        "Dockerfile"
    )
    
    missing_files=()
    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            missing_files+=("$file")
        fi
    done
    
    if [ ${#missing_files[@]} -gt 0 ]; then
        print_warning "Missing required files:"
        printf ' • %s\n' "${missing_files[@]}"
        print_info "Please ensure all artifact files are created first"
        return 1
    fi
    
    # Rename the updated streamlit file
    if [ -f "updated_streamlit_docker.py" ] && [ ! -f "streamlit_app.py" ]; then
        mv updated_streamlit_docker.py streamlit_app.py
        print_status "Updated Streamlit app file"
    fi
    
    print_status "All required files are present"
}

# Update requirements for Docker
update_requirements() {
    print_info "Updating requirements.txt for Docker environment..."
    
    cat > requirements.txt << 'EOF'
streamlit==1.28.1
pandas==2.1.3
numpy==1.24.3
scikit-learn==1.3.2
plotly==5.17.0
requests==2.31.0
python-pptx==0.6.22
openpyxl==3.1.2
matplotlib==3.8.2
seaborn==0.13.0
transformers==4.35.0
torch==2.0.1
tokenizers==0.14.1
EOF

    print_status "Requirements updated for Docker environment"
}

# Build and start services
start_services() {
    print_info "Building and starting services..."
    
    # Build the main application
    print_info "Building log analyzer container..."
    docker-compose build log-analyzer
    
    if [ $? -ne 0 ]; then
        print_error "Failed to build log analyzer container"
        return 1
    fi
    
    # Start all services
    print_info "Starting all services..."
    docker-compose up -d
    
    if [ $? -ne 0 ]; then
        print_error "Failed to start services"
        return 1
    fi
    
    print_status "Services started successfully"
}

# Wait for services to be ready
wait_for_services() {
    print_info "Waiting for services to be ready..."
    
    # Wait for main application
    print_info "Waiting for Streamlit application..."
    for i in {1..30}; do
        if curl -s http://localhost:8501/_stcore/health > /dev/null 2>&1; then
            print_status "Streamlit application is ready"
            break
        fi
        
        if [ $i -eq 30 ]; then
            print_warning "Streamlit application may not be ready yet"
            break
        fi
        
        sleep 2
    done
    
    # Wait for Ollama service
    print_info "Waiting for Ollama service..."
    for i in {1..20}; do
        if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
            print_status "Ollama service is ready"
            break
        fi
        
        if [ $i -eq 20 ]; then
            print_warning "Ollama service may not be ready yet"
            break
        fi
        
        sleep 3
    done
}

# Download LLaMA2 model
setup_llama_model() {
    print_info "Setting up LLaMA2 model..."
    
    # Check if Ollama is responding
    if ! curl -s http://localhost:11434/api/tags > /dev/null; then
        print_warning "Ollama service not responding, skipping model download"
        return 1
    fi
    
    print_info "Downloading LLaMA2 model (this may take several minutes)..."
    
    # Download the model
    docker-compose exec -T ollama ollama pull llama2
    
    if [ $? -eq 0 ]; then
        print_status "LLaMA2 model downloaded successfully"
        
        # Test the model
        print_info "Testing LLaMA2 model..."
        TEST_RESPONSE=$(docker-compose exec -T ollama ollama run llama2 "Say 'Working' if you can process this" 2>/dev/null | head -1)
        
        if [[ "$TEST_RESPONSE" == *"Working"* ]] || [[ "$TEST_RESPONSE" == *"working"* ]]; then
            print_status "LLaMA2 model is working correctly"
            return 0
        else
            print_warning "LLaMA2 model test unclear, but download completed"
            return 0
        fi
    else
        print_error "Failed to download LLaMA2 model"
        print_info "The application will still work with fallback responses"
        return 1
    fi
}

# Create test data
create_test_data() {
    print_info "Creating test data..."
    
    # Ensure logs directory exists
    mkdir -p logs
    
    # Create sample security log
    cat > logs/security.log << 'EOF'
2024-08-29 09:15:23 [INFO] auth: Successful login for user jdoe from 192.168.1.100
2024-08-29 09:16:45 [INFO] auth: Successful login for user admin from 192.168.1.101
2024-08-29 09:17:12 [WARN] auth: Failed login attempt for user admin from 203.0.113.10
2024-08-29 09:17:15 [WARN] auth: Failed login attempt for user admin from 203.0.113.10
2024-08-29 09:17:18 [ERROR] auth: Failed login attempt for user admin from 203.0.113.10
2024-08-29 09:17:21 [ERROR] auth: Multiple failed login attempts detected for user admin from 203.0.113.10
2024-08-29 09:20:30 [INFO] auth: Successful login for user ssmith from 192.168.1.102
2024-08-29 10:05:45 [ERROR] system: Database connection timeout
2024-08-29 10:06:12 [ERROR] system: Service restart failed
2024-08-29 10:15:33 [INFO] auth: User admin logged out
2024-08-29 11:30:22 [WARN] vault: Unauthorized access attempt to secret/database/prod
2024-08-29 11:31:15 [ERROR] vault: Failed to authenticate token for secret/database/prod
2024-08-29 14:22:33 [INFO] backup: Daily backup started for database_prod
2024-08-29 14:45:12 [ERROR] backup: Backup failed for database_prod - storage unreachable
2024-08-29 15:00:00 [INFO] backup: Retry backup for database_prod
2024-08-29 15:20:45 [INFO] backup: Backup completed successfully for database_prod
EOF

    # Create sample backup log
    cat > logs/backup.log << 'EOF'
2024-08-29 02:00:00 INFO database_prod: Backup started
2024-08-29 02:15:30 INFO database_prod: Backup completed successfully, 1.2GB in 15min
2024-08-29 02:30:00 INFO fileserver_backup: Backup started
2024-08-29 02:45:22 ERROR fileserver_backup: Backup failed - Cannot connect to storage backend
2024-08-29 03:00:00 INFO user_data: Backup started
2024-08-29 03:20:15 INFO user_data: Backup completed successfully, 850MB in 20min
2024-08-29 03:30:00 ERROR config_backup: Backup failed - Permission denied
2024-08-29 04:00:00 INFO vault_backup: Backup started
2024-08-29 04:10:33 ERROR vault_backup: Backup failed - Vault unsealed, cannot backup
EOF

    print_status "Test data created"
}

# Display service information
show_service_info() {
    print_info "Service Information:"
    
    echo ""
    echo "🌐 Web Interfaces:"
    echo "   • Main Application:  http://localhost:8501"
    echo "   • Grafana Dashboard: http://localhost:3000 (admin/admin123)"
    echo "   • Prometheus:        http://localhost:9090"
    
    echo ""
    echo "🤖 AI Services:"
    echo "   • Ollama API:        http://localhost:11434"
    echo "   • Text Generation:   http://localhost:7860 (optional)"
    
    echo ""
    echo "📊 Features Available:"
    echo "   • Interactive log analysis dashboard"
    echo "   • Natural language AI chat interface"
    echo "   • Real-time anomaly detection"
    echo "   • PowerPoint report generation"
    echo "   • Multiple visualization options"
    
    echo ""
    echo "🔧 Management Commands:"
    echo "   • View logs:         docker-compose logs -f log-analyzer"
    echo "   • Stop services:     docker-compose down"
    echo "   • Restart:           docker-compose restart"
    echo "   • Update:            docker-compose pull && docker-compose up -d"
    
    echo ""
}

# Test the complete setup
test_setup() {
    print_info "Testing complete setup..."
    
    # Test main application
    if curl -s http://localhost:8501 > /dev/null; then
        print_status "✅ Main application is accessible"
    else
        print_warning "⚠️ Main application may not be ready yet"
    fi
    
    # Test Ollama
    if curl -s http://localhost:11434/api/tags > /dev/null; then
        print_status "✅ Ollama service is accessible"
        
        # Test model availability
        MODELS=$(curl -s http://localhost:11434/api/tags | grep -o '"name":"[^"]*"' | head -1)
        if [ ! -z "$MODELS" ]; then
            print_status "✅ LLM models are available"
        else
            print_warning "⚠️ No LLM models found (may still be downloading)"
        fi
    else
        print_warning "⚠️ Ollama service not accessible"
    fi
    
    # Test container status
    print_info "Container Status:"
    docker-compose ps
}

# Main setup function
main() {
    echo ""
    print_info "Starting complete Docker setup..."
    
    # Run setup steps
    check_docker
    
    if ! create_project_files; then
        print_error "Setup failed - missing required files"
        exit 1
    fi
    
    update_requirements
    create_test_data
    
    # Build and start services
    if ! start_services; then
        print_error "Failed to start services"
        exit 1
    fi
    
    # Wait for services
    wait_for_services
    
    # Setup LLaMA model (non-blocking)
    print_info "Setting up AI models in background..."
    setup_llama_model &
    LLAMA_PID=$!
    
    # Show service info
    show_service_info
    
    # Test setup
    test_setup
    
    # Wait for LLaMA setup to complete
    print_info "Waiting for LLaMA model setup to complete..."
    wait $LLAMA_PID
    
    echo ""
    print_status "🎉 Complete Docker setup finished!"
    echo ""
    print_info "Next steps:"
    echo "1. Open http://localhost:8501 in your browser"
    echo "2. Click 'Use Sample Data' to load test data"
    echo "3. Try the AI Chat tab for natural language queries"
    echo "4. Test queries like:"
    echo "   • 'Summarize top 3 suspicious activities in last 24h'"
    echo "   • 'Which vaults had most failed restores this week?'"
    echo ""
    print_warning "Note: LLM responses may be slower on first use as models initialize"
    echo ""
}

# Cleanup function for interrupts
cleanup() {
    print_info "Cleaning up..."
    docker-compose down
    exit 1
}

trap cleanup INT

# Run main function
