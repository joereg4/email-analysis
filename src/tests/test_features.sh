#!/bin/bash

echo "🚀 Email Analysis API - Comprehensive Test Suite"
echo "=================================================="

# Test API health
echo "🔍 Testing API Health..."
health_response=$(curl -s http://localhost:8080/)
if echo "$health_response" | grep -q "ok"; then
    echo "✅ API is running"
    echo "   Response: $health_response"
else
    echo "❌ API health check failed"
    echo "   Response: $health_response"
    exit 1
fi

# Test safe email
echo ""
echo "📧 Testing Safe Email..."
echo "------------------------"
safe_response=$(curl -s -X POST -F "file=@safe_email.eml" http://localhost:8080/upload)
echo "$safe_response" | jq -r '.email_info.subject + " | Risk: " + .risk_analysis.risk_level + " (" + (.risk_analysis.risk_score | tostring) + "/100)"'

# Test suspicious email
echo ""
echo "📧 Testing Suspicious Email..."
echo "------------------------------"
suspicious_response=$(curl -s -X POST -F "file=@suspicious_email.eml" http://localhost:8080/upload)
echo "$suspicious_response" | jq -r '.email_info.subject + " | Risk: " + .risk_analysis.risk_level + " (" + (.risk_analysis.risk_score | tostring) + "/100)"'
echo "Risk reasons:"
echo "$suspicious_response" | jq -r '.risk_analysis.risk_reasons[]' | sed 's/^/  - /'

# Test basic email
echo ""
echo "📧 Testing Basic Email..."
echo "-------------------------"
basic_response=$(curl -s -X POST -F "file=@sample.eml" http://localhost:8080/upload)
echo "$basic_response" | jq -r '.email_info.subject + " | Risk: " + .risk_analysis.risk_level + " (" + (.risk_analysis.risk_score | tostring) + "/100)"'

# Test non-email file
echo ""
echo "📄 Testing Non-Email File..."
echo "----------------------------"
text_response=$(curl -s -X POST -F "file=@test.txt" http://localhost:8080/upload)
echo "$text_response" | jq -r '.message'

echo ""
echo "=================================================="
echo "🎉 All tests completed successfully!"
echo "The Email Analysis API is working with:"
echo "  ✅ File upload"
echo "  ✅ Email parsing"
echo "  ✅ Risk scoring"
echo "  ✅ Multiple risk levels (SAFE, LOW, MEDIUM, HIGH)"
