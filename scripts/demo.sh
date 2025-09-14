#!/bin/bash

# Email Analysis Sandbox Demo Script

echo "🎬 Email Analysis Sandbox Demo"
echo "================================"
echo ""

# Check if services are running
echo "🔍 Checking if services are running..."

if curl -s http://localhost:8080/ > /dev/null 2>&1; then
    echo "✅ API is running on http://localhost:8080"
else
    echo "❌ API is not running. Please run: ./setup.sh"
    exit 1
fi

if curl -s http://localhost:8501/ > /dev/null 2>&1; then
    echo "✅ Web UI is running on http://localhost:8501"
else
    echo "❌ Web UI is not running. Please run: ./setup.sh"
    exit 1
fi

echo ""
echo "🌐 Opening the Web UI in your browser..."
echo ""

# Try to open the web UI in the default browser
if command -v open &> /dev/null; then
    open http://localhost:8501
elif command -v xdg-open &> /dev/null; then
    xdg-open http://localhost:8501
elif command -v start &> /dev/null; then
    start http://localhost:8501
else
    echo "Please open http://localhost:8501 in your browser"
fi

echo "📋 Demo Instructions:"
echo "===================="
echo ""
echo "1. 🌐 The Web UI should now be open in your browser"
echo "2. 📤 Go to the 'Upload Email' section in the sidebar"
echo "3. 📁 Click 'Choose an .eml file' and select the sample email:"
echo "   ./sample_email.eml"
echo "4. 🚀 Click 'Analyze Email' to start the analysis"
echo "5. ⏳ Wait for the analysis to complete (usually 30-60 seconds)"
echo "6. 📊 View the results in the 'Dashboard' and 'Email List' tabs"
echo "7. 🔍 Click 'View Details' on any email to see detailed analysis"
echo ""
echo "🎯 What you'll see:"
echo "   - Risk scores and threat levels"
echo "   - AI-powered analysis and recommendations"
echo "   - Visual charts and dashboards"
echo "   - Easy-to-understand threat indicators"
echo ""
echo "🔧 Alternative: You can also drop .eml files directly into:"
echo "   ./data/inbox/"
echo "   The system will automatically detect and process them"
echo ""
echo "📚 For more information, check the README.md file"
echo ""
echo "🚀 Happy analyzing!"
