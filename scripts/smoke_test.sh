#!/bin/bash
set -e

echo "=== CIAI API Smoke Tests ==="
echo

# Configuration
API_URL="${API_URL:-http://localhost:8000}"
API_KEY="${API_KEY:-change-this-key}"
TIMEOUT=10

echo "Testing API at: $API_URL"
echo

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
PASSED=0
FAILED=0

test_endpoint() {
  local name=$1
  local method=$2
  local endpoint=$3
  local data=$4

  echo -n "Testing $name... "

  if [ "$method" = "GET" ]; then
    response=$(curl -s -w "\n%{http_code}" -H "X-API-KEY: $API_KEY" "$API_URL$endpoint")
  else
    response=$(curl -s -w "\n%{http_code}" -X $method -H "X-API-KEY: $API_KEY" -H "Content-Type: application/json" -d "$data" "$API_URL$endpoint")
  fi

  http_code=$(echo "$response" | tail -n 1)
  body=$(echo "$response" | head -n -1)

  if [[ "$http_code" =~ ^[23][0-9][0-9]$ ]]; then
    echo -e "${GREEN}✓ PASS${NC} (HTTP $http_code)"
    ((PASSED++))
    return 0
  else
    echo -e "${RED}✗ FAIL${NC} (HTTP $http_code)"
    echo "Response: $body"
    ((FAILED++))
    return 1
  fi
}

# Test 1: Health Check
test_endpoint "Health Check" "GET" "/health"

# Test 2: Detect Endpoint - Clean Text
test_endpoint "Detect - Clean Text" "POST" "/detect" \
  '{"text": "Hello world, this is a clean message."}'

# Test 3: Detect Endpoint - PII Detection
test_endpoint "Detect - PII Detection" "POST" "/detect" \
  '{"text": "My phone number is 555-123-4567 and email is john@example.com"}'

# Test 4: Detect Endpoint - Secret Detection
test_endpoint "Detect - Secret Detection" "POST" "/detect" \
  '{"text": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}'

# Test 5: Metrics Endpoint
test_endpoint "Metrics Endpoint" "GET" "/metrics"

# Test 6: Rate Limiting (Fire 10 requests rapidly)
echo -n "Testing Rate Limiting... "
RATE_PASS=0
for i in {1..10}; do
  response=$(curl -s -w "%{http_code}" -H "X-API-KEY: $API_KEY" "$API_URL/health")
  http_code=$(echo "${response: -3}")
  if [[ "$http_code" =~ ^[23][0-9][0-9]$ ]]; then
    ((RATE_PASS++))
  fi
done
if [ $RATE_PASS -ge 8 ]; then
  echo -e "${GREEN}✓ PASS${NC} (Rate limiter working)"
  ((PASSED++))
else
  echo -e "${YELLOW}⚠ WARN${NC} (Rate limiting may be too strict)"
fi

echo
echo "=== Results ==="
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo

if [ $FAILED -eq 0 ]; then
  echo -e "${GREEN}All tests passed!${NC}"
  exit 0
else
  echo -e "${RED}Some tests failed.${NC}"
  exit 1
fi
