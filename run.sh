#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print status messages
print_status() {
    echo -e "${BLUE}[*] $1${NC}"
}

print_success() {
    echo -e "${GREEN}[+] $1${NC}"
}

print_error() {
    echo -e "${RED}[-] $1${NC}"
}

# Check if ZAP is installed
check_zap() {
    if ! command -v zaproxy &> /dev/null; then
        print_error "OWASP ZAP not found! Please install it first."
        exit 1
    fi
}

# Setup Python virtual environment
setup_venv() {
    print_status "Setting up Python virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
}

# Install frontend dependencies
setup_frontend() {
    print_status "Setting up frontend dependencies..."
    cd frontend
    npm install
    cd ..
}

# Start services
start_services() {
    # Start ZAP
    print_status "Starting OWASP ZAP..."
    nohup zaproxy -daemon -port 8080 -host 127.0.0.1 > logs/zap.log 2>&1 &
    sleep 15 # Wait for ZAP to initialize

    # Start backend
    print_status "Starting Flask backend server..."
    cd backend
    nohup python server.py > ../logs/backend.log 2>&1 &
    cd ..
    sleep 10

    # Start frontend
    print_status "Starting React frontend..."
    cd frontend
    npm i
    npm run dev &
    cd ..
}

# Main deployment function
deploy() {
    print_status "Starting deployment process..."

    # Check requirements
    check_zap

    # Setup environments
    setup_venv
    setup_frontend

    # Start all services
    start_services

    # Final status
    print_success "Deployment completed!"
    print_success "Frontend is running at: http://localhost:5173"
    print_success "Backend API available at: http://localhost:5000/api"
    print_success "Logs available in the logs directory"

    # Print monitoring instructions
    echo -e "\n${BLUE}To monitor the services:${NC}"
    echo "- ZAP logs: tail -f logs/zap.log"
    echo "- Backend logs: tail -f logs/backend.log"
    
    # Print shutdown instructions
    echo -e "\n${BLUE}To shutdown all services:${NC}"
    echo "./shutdown.sh"
}

# Run deployment
deploy