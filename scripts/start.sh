#!/bin/bash

# Email Analysis Sandbox Startup Script

echo "Starting Email Analysis Sandbox..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "Error: docker-compose is not installed. Please install docker-compose and try again."
    exit 1
fi

# Create necessary directories
echo "Creating directories..."
mkdir -p data/{inbox,quarantine,artifacts,db,logs}

# Check if .env file exists
if [ ! -f .env ]; then
    echo "Warning: .env file not found. Creating from config.env..."
    if [ -f config.env ]; then
        cp config.env .env
        echo "Please edit .env file with your API keys before starting the services."
        echo "Required: OPENAI_API_KEY, VIRUSTOTAL_API_KEY (optional)"
        read -p "Press Enter to continue after editing .env file..."
    else
        echo "Error: config.env file not found. Please create .env file with required configuration."
        exit 1
    fi
fi

# Build and start services
echo "Building and starting services..."
docker-compose up --build -d

# Wait for services to start
echo "Waiting for services to start..."
sleep 10

# Check service status
echo "Checking service status..."
docker-compose ps

# Display access information
echo ""
echo "Email Analysis Sandbox is now running!"
echo ""
echo "Access points:"
echo "  - API: http://localhost:8080"
echo "  - API Docs: http://localhost:8080/docs"
echo "  - Inbox: ./data/inbox/ (drop .eml files here)"
echo "  - Logs: ./data/logs/"
echo "  - Database: ./data/db/email_analysis.db"
echo ""
echo "To stop the services:"
echo "  docker-compose down"
echo ""
echo "To view logs:"
echo "  docker-compose logs -f"
echo ""
echo "To restart a specific service:"
echo "  docker-compose restart <service-name>"
echo ""
echo "Services:"
echo "  - api: FastAPI gateway"
echo "  - worker: Background processing"
echo "  - watcher: File monitoring"
echo "  - redis: Job queue"
echo "  - clamav: Antivirus scanning"
echo ""
echo "Happy analyzing! 🚀"
