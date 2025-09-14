#!/bin/bash

echo "🚀 Starting Email Analysis Sandbox..."
echo "====================================="

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker Desktop first."
    exit 1
fi

# Start all services
echo "📦 Starting Docker services..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 10

# Check API health
echo "🔍 Checking API health..."
if curl -s http://localhost:8080/ > /dev/null; then
    echo "✅ API is running at http://localhost:8080"
else
    echo "❌ API failed to start"
    exit 1
fi

# Check Web UI health
echo "🌐 Checking Web UI health..."
if curl -s http://localhost:8501/ > /dev/null; then
    echo "✅ Web UI is running at http://localhost:8501"
else
    echo "❌ Web UI failed to start"
    exit 1
fi

echo ""
echo "🎉 Email Analysis Sandbox is ready!"
echo "====================================="
echo "📧 Web UI: http://localhost:8501"
echo "🔧 API: http://localhost:8080"
echo "📚 API Docs: http://localhost:8080/docs"
echo ""
echo "📁 Sample files available in: samples/"
echo "🧪 Run tests with: ./src/tests/test-scanning.sh"
echo ""
echo "To stop services: docker-compose down"
