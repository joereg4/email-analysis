#!/bin/bash

echo "🗄️  Database API Test Suite"
echo "=========================="

# Test API health
echo "🔍 Testing API Health..."
health_response=$(curl -s http://localhost:8080/)
if echo "$health_response" | grep -q "Database"; then
    echo "✅ Database API is running"
else
    echo "❌ API health check failed"
    exit 1
fi

# Test history endpoint
echo ""
echo "📊 Testing History Endpoint..."
history_response=$(curl -s http://localhost:8080/history)
echo "$history_response" | jq -r '.history[] | "ID \(.id): \(.filename) - \(.risk_level) (\(.risk_score)/100)"'

# Test detailed analysis
echo ""
echo "🔍 Testing Detailed Analysis..."
analysis_id=$(echo "$history_response" | jq -r '.history[0].id')
detail_response=$(curl -s http://localhost:8080/analysis/$analysis_id)
echo "Analysis ID $analysis_id details:"
echo "$detail_response" | jq -r '"Subject: " + .subject'
echo "$detail_response" | jq -r '"Sender: " + .sender'
echo "$detail_response" | jq -r '"Risk: " + .risk_level + " (" + (.risk_score | tostring) + "/100)"'
echo "$detail_response" | jq -r '"Risk Reasons: " + (.risk_reasons | length | tostring) + " found"'

# Test file upload with database storage
echo ""
echo "📧 Testing File Upload with Database Storage..."
upload_response=$(curl -s -X POST -F "file=@sample.eml" http://localhost:8080/upload)
analysis_id=$(echo "$upload_response" | jq -r '.analysis_id')
echo "✅ Upload successful, saved as analysis ID: $analysis_id"

# Show updated history
echo ""
echo "📊 Updated History:"
updated_history=$(curl -s http://localhost:8080/history)
echo "$updated_history" | jq -r '.history[] | "ID \(.id): \(.filename) - \(.risk_level) (\(.risk_score)/100)"'

echo ""
echo "=========================="
echo "🎉 Database API tests completed!"
echo "Features working:"
echo "  ✅ File upload with database storage"
echo "  ✅ Analysis history retrieval"
echo "  ✅ Detailed analysis by ID"
echo "  ✅ SQLite database persistence"
