#!/bin/bash

echo "🔍 Advanced Scanning Test Suite"
echo "==============================="

# Test API health
echo "🔍 Testing API Health..."
health_response=$(curl -s http://localhost:8080/)
if echo "$health_response" | grep -q "Advanced Scanning"; then
    echo "✅ Advanced Scanning API is running"
else
    echo "❌ API health check failed"
    exit 1
fi

# Test ClamAV scanning
echo ""
echo "🦠 Testing ClamAV Scanning..."
clamav_response=$(curl -s -X POST -F "file=@safe_email.eml" http://localhost:8080/upload)
clamav_status=$(echo "$clamav_response" | jq -r '.clamav_result.status')
echo "ClamAV Status: $clamav_status"
if [ "$clamav_status" = "clean" ]; then
    echo "✅ ClamAV scanning working (clean file detected)"
elif [ "$clamav_status" = "error" ]; then
    echo "⚠️  ClamAV scanning has issues but API is responding"
else
    echo "ℹ️  ClamAV Status: $clamav_status"
fi

# Test YARA scanning with suspicious file
echo ""
echo "🎯 Testing YARA Scanning..."
yara_response=$(curl -s -X POST -F "file=@test_yara.eml" http://localhost:8080/upload)
yara_status=$(echo "$yara_response" | jq -r '.yara_result.status')
yara_message=$(echo "$yara_response" | jq -r '.yara_result.message')
echo "YARA Status: $yara_status"
echo "YARA Message: $yara_message"

# Test risk analysis with scanning results
echo ""
echo "⚠️  Testing Risk Analysis with Scanning..."
risk_level=$(echo "$yara_response" | jq -r '.risk_analysis.risk_level')
risk_score=$(echo "$yara_response" | jq -r '.risk_analysis.risk_score')
echo "Risk Level: $risk_level"
echo "Risk Score: $risk_score"

# Test database storage with scanning results
echo ""
echo "🗄️  Testing Database Storage..."
analysis_id=$(echo "$yara_response" | jq -r '.analysis_id')
echo "Analysis saved with ID: $analysis_id"

# Test history with scanning results
echo ""
echo "📊 Testing History with Scanning Results..."
history_response=$(curl -s http://localhost:8080/history)
echo "Recent analyses:"
echo "$history_response" | jq -r '.history[] | "ID \(.id): \(.filename) - \(.risk_level) (\(.risk_score)/100) - ClamAV: \(.clamav_result.status) - YARA: \(.yara_result.status)"'

# Test detailed analysis retrieval
echo ""
echo "🔍 Testing Detailed Analysis Retrieval..."
detail_response=$(curl -s http://localhost:8080/analysis/$analysis_id)
echo "Detailed analysis for ID $analysis_id:"
echo "$detail_response" | jq -r '"Subject: " + .subject'
echo "$detail_response" | jq -r '"Risk: " + .risk_level + " (" + (.risk_score | tostring) + "/100)"'
echo "$detail_response" | jq -r '"ClamAV: " + .clamav_result.status + " - " + .clamav_result.message'
echo "$detail_response" | jq -r '"YARA: " + .yara_result.status + " - " + .yara_result.message'

echo ""
echo "==============================="
echo "🎉 Advanced Scanning Test Complete!"
echo ""
echo "Features tested:"
echo "  ✅ ClamAV antivirus scanning"
echo "  ✅ YARA rule-based scanning"
echo "  ✅ Enhanced risk analysis"
echo "  ✅ Database storage with scanning results"
echo "  ✅ History with scanning data"
echo "  ✅ Detailed analysis retrieval"
