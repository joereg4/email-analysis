#!/bin/bash

echo "🧪 COMPREHENSIVE EMAIL ANALYSIS TEST SUITE"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_result="$3"
    
    echo -n "Testing $test_name... "
    
    if eval "$test_command" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ PASS${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${RED}❌ FAIL${NC}"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Function to test API response
test_api_response() {
    local endpoint="$1"
    local expected_key="$2"
    local test_name="$3"
    
    echo -n "Testing $test_name... "
    
    response=$(curl -s "$endpoint" 2>/dev/null)
    if echo "$response" | grep -q "$expected_key"; then
        echo -e "${GREEN}✅ PASS${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${RED}❌ FAIL${NC}"
        echo "  Expected: $expected_key"
        echo "  Got: $response"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Function to test file upload
test_file_upload() {
    local file="$1"
    local expected_risk="$2"
    local test_name="$3"
    
    echo -n "Testing $test_name... "
    
    if [ ! -f "$file" ]; then
        echo -e "${RED}❌ FAIL - File not found: $file${NC}"
        ((TESTS_FAILED++))
        return 1
    fi
    
    response=$(curl -s -X POST -F "file=@$file" http://localhost:8080/upload 2>/dev/null)
    if echo "$response" | grep -q '"success":true' && echo "$response" | grep -q "$expected_risk"; then
        echo -e "${GREEN}✅ PASS${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${RED}❌ FAIL${NC}"
        echo "  Expected: success=true and risk=$expected_risk"
        echo "  Got: $response"
        ((TESTS_FAILED++))
        return 1
    fi
}

echo "🔍 PHASE 1: DOCKER SERVICES"
echo "=========================="

# Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 10

# Test Docker services are running
run_test "Docker services running" "docker-compose ps | grep -q 'Up'"

echo ""
echo "🌐 PHASE 2: API ENDPOINTS"
echo "========================"

# Test API health
test_api_response "http://localhost:8080/" "Email Analysis API" "API Health Check"

# Test API endpoints exist
test_api_response "http://localhost:8080/history" "history" "History Endpoint"
test_api_response "http://localhost:8080/docs" "swagger" "API Documentation"

echo ""
echo "📧 PHASE 3: EMAIL ANALYSIS"
echo "========================="

# Test file uploads with different risk levels
test_file_upload "samples/safe_email.eml" "SAFE" "Safe Email Analysis"
test_file_upload "samples/suspicious_email.eml" "HIGH" "Suspicious Email Analysis"

echo ""
echo "🔍 PHASE 4: SCANNING CAPABILITIES"
echo "================================"

# Test ClamAV scanning
echo -n "Testing ClamAV scanning... "
clamav_test=$(curl -s -X POST -F "file=@samples/safe_email.eml" http://localhost:8080/upload 2>/dev/null)
if echo "$clamav_test" | grep -q "clamav_result"; then
    echo -e "${GREEN}✅ PASS${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ FAIL${NC}"
    ((TESTS_FAILED++))
fi

# Test YARA scanning
echo -n "Testing YARA scanning... "
yara_test=$(curl -s -X POST -F "file=@samples/suspicious_email.eml" http://localhost:8080/upload 2>/dev/null)
if echo "$yara_test" | grep -q "yara_result"; then
    echo -e "${GREEN}✅ PASS${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ FAIL${NC}"
    ((TESTS_FAILED++))
fi

echo ""
echo "🗄️ PHASE 5: DATABASE FUNCTIONALITY"
echo "================================="

# Test database storage
echo -n "Testing database storage... "
db_test=$(curl -s -X POST -F "file=@samples/safe_email.eml" http://localhost:8080/upload 2>/dev/null)
if echo "$db_test" | grep -q "analysis_id"; then
    echo -e "${GREEN}✅ PASS${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ FAIL${NC}"
    ((TESTS_FAILED++))
fi

# Test history retrieval
test_api_response "http://localhost:8080/history" "count" "History Retrieval"

echo ""
echo "🌐 PHASE 6: WEB UI"
echo "================="

# Test Web UI is accessible
run_test "Web UI accessible" "curl -s http://localhost:8501/ | grep -q 'Streamlit'"

# Test Web UI can connect to API
echo -n "Testing Web UI API connection... "
web_ui_test=$(curl -s http://localhost:8501/ 2>/dev/null)
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ PASS${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ FAIL${NC}"
    ((TESTS_FAILED++))
fi

echo ""
echo "📊 PHASE 7: INTEGRATION TESTS"
echo "============================"

# Test end-to-end workflow
echo -n "Testing end-to-end workflow... "
workflow_test=$(curl -s -X POST -F "file=@samples/suspicious_email.eml" http://localhost:8080/upload 2>/dev/null)
if echo "$workflow_test" | grep -q '"success":true' && \
   echo "$workflow_test" | grep -q "risk_analysis" && \
   echo "$workflow_test" | grep -q "clamav_result" && \
   echo "$workflow_test" | grep -q "yara_result"; then
    echo -e "${GREEN}✅ PASS${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ FAIL${NC}"
    ((TESTS_FAILED++))
fi

echo ""
echo "🎯 FINAL RESULTS"
echo "==============="
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL TESTS PASSED! System is fully operational.${NC}"
    echo ""
    echo "🌐 Access URLs:"
    echo "  Web UI: http://localhost:8501"
    echo "  API: http://localhost:8080"
    echo "  API Docs: http://localhost:8080/docs"
    echo ""
    echo "📧 Sample files available in: samples/"
    exit 0
else
    echo -e "${RED}❌ $TESTS_FAILED TESTS FAILED! System has issues.${NC}"
    echo ""
    echo "🔧 Troubleshooting:"
    echo "  1. Check Docker services: docker-compose ps"
    echo "  2. Check API logs: docker-compose logs api"
    echo "  3. Check Web UI logs: docker-compose logs web-ui"
    echo "  4. Restart services: docker-compose restart"
    exit 1
fi
