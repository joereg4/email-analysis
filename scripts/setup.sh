#!/bin/bash

# Email Analysis Sandbox Setup Script

echo "🔧 Setting up Email Analysis Sandbox..."

# Check if .env file exists
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    if [ -f env.sample ]; then
        cp env.sample .env
        echo "✅ .env file created from env.sample"
        echo ""
        echo "⚠️  IMPORTANT: Please edit the .env file and add your API keys:"
        echo "   - OPENAI_API_KEY (required for AI analysis)"
        echo "   - VIRUSTOTAL_API_KEY (optional for URL analysis)"
        echo ""
        echo "📖 Get your API keys from:"
        echo "   - OpenAI: https://platform.openai.com/api-keys"
        echo "   - VirusTotal: https://www.virustotal.com/gui/my-apikey"
        echo ""
        read -p "Press Enter after you've updated the .env file with your API keys..."
    else
        echo "❌ Error: env.sample file not found!"
        exit 1
    fi
else
    echo "✅ .env file already exists"
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p data/{inbox,quarantine,artifacts,db,logs}
echo "✅ Directories created"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Error: Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Error: docker-compose is not installed. Please install docker-compose and try again."
    exit 1
fi

echo "✅ Docker and docker-compose are available"

# Build and start services
echo "🐳 Building and starting services..."
docker-compose up --build -d

# Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 15

# Check service status
echo "📊 Checking service status..."
docker-compose ps

# Test API endpoint
echo "🔍 Testing API endpoint..."
sleep 5
if curl -s http://localhost:8080/ > /dev/null; then
    echo "✅ API is responding"
else
    echo "⚠️  API might still be starting up..."
fi

echo ""
echo "🎉 Setup complete!"
echo ""
echo "📋 Next steps:"
echo "   1. 🌐 Open the Web UI: http://localhost:8501"
echo "   2. 📤 Upload .eml files via the web interface"
echo "   3. 📊 View analysis results and dashboards"
echo "   4. 📁 Or drop .eml files into: ./data/inbox/"
echo ""
echo "🔧 Management commands:"
echo "   - View logs: docker-compose logs -f"
echo "   - Stop services: docker-compose down"
echo "   - Restart: docker-compose restart"
echo ""
echo "🌐 Access Points:"
echo "   - Web UI: http://localhost:8501 (User-friendly interface)"
echo "   - API: http://localhost:8080"
echo "   - API Docs: http://localhost:8080/docs"
echo ""
echo "📁 Important directories:"
echo "   - Inbox: ./data/inbox/ (drop emails here)"
echo "   - Logs: ./data/logs/"
echo "   - Database: ./data/db/email_analysis.db"
echo "   - Quarantine: ./data/quarantine/"
echo ""
echo "🚀 Happy analyzing!"
