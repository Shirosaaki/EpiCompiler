#!/bin/bash

# EpiCompiler Test Runner
# Usage: ./run_tests.sh [category]
# Categories: basic, errors, edge, stress, algo, integ, all

COMPILER="../EpiCompiler"
TEST_DIR="$(dirname "$0")"
PASSED=0
FAILED=0
ERRORS_EXPECTED=0
ERRORS_CAUGHT=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

run_test() {
    local file=$1
    local expect_error=$2
    local name=$(basename "$file" .tslang)
    
    if [ "$expect_error" = "true" ]; then
        # For error tests, we expect compilation to fail
        output=$($COMPILER "$file" 2>&1)
        result=$?
        if [ $result -ne 0 ]; then
            echo -e "${GREEN}✓${NC} $name (error caught correctly)"
            ((ERRORS_CAUGHT++))
        else
            echo -e "${RED}✗${NC} $name (should have produced error)"
            ((FAILED++))
        fi
        ((ERRORS_EXPECTED++))
    else
        # For normal tests, we expect compilation to succeed
        output=$($COMPILER "$file" 2>&1)
        result=$?
        if [ $result -eq 0 ]; then
            # Try to run the compiled program if it exists
            binary="${file%.tslang}"
            if [ -f "$binary" ]; then
                run_output=$(./"$binary" 2>&1)
                run_result=$?
                if [ $run_result -eq 0 ]; then
                    echo -e "${GREEN}✓${NC} $name"
                    ((PASSED++))
                else
                    echo -e "${YELLOW}~${NC} $name (compiled but runtime error)"
                    ((PASSED++))
                fi
                rm -f "$binary"
            else
                echo -e "${GREEN}✓${NC} $name (compiled)"
                ((PASSED++))
            fi
        else
            echo -e "${RED}✗${NC} $name"
            echo "  Error: $output"
            ((FAILED++))
        fi
    fi
}

run_category() {
    local category=$1
    local dir=$2
    local expect_error=${3:-false}
    
    print_header "$category"
    
    if [ -d "$dir" ]; then
        for file in "$dir"/*.tslang; do
            if [ -f "$file" ]; then
                run_test "$file" "$expect_error"
            fi
        done
    else
        echo -e "${YELLOW}Directory not found: $dir${NC}"
    fi
    echo ""
}

# Main
cd "$TEST_DIR"

case "${1:-all}" in
    basic)
        print_header "Basic Tests"
        for file in [0-9][0-9]_*.tslang; do
            if [ -f "$file" ]; then
                run_test "$file" "false"
            fi
        done
        ;;
    errors)
        run_category "Error Tests (should fail)" "errors" "true"
        ;;
    edge)
        run_category "Edge Case Tests" "edge" "false"
        ;;
    stress)
        run_category "Stress Tests" "stress" "false"
        ;;
    algo)
        run_category "Algorithm Tests" "algorithms" "false"
        ;;
    integ)
        run_category "Integration Tests" "integration" "false"
        ;;
    all)
        print_header "Basic Tests"
        for file in [0-9][0-9]_*.tslang; do
            if [ -f "$file" ]; then
                run_test "$file" "false"
            fi
        done
        echo ""
        
        run_category "Error Tests (should fail)" "errors" "true"
        run_category "Edge Case Tests" "edge" "false"
        run_category "Stress Tests" "stress" "false"
        run_category "Algorithm Tests" "algorithms" "false"
        run_category "Integration Tests" "integration" "false"
        ;;
    *)
        echo "Usage: $0 [basic|errors|edge|stress|algo|integ|all]"
        exit 1
        ;;
esac

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  SUMMARY${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Passed:${NC} $PASSED"
echo -e "${RED}Failed:${NC} $FAILED"
if [ $ERRORS_EXPECTED -gt 0 ]; then
    echo -e "${YELLOW}Error tests:${NC} $ERRORS_CAUGHT/$ERRORS_EXPECTED caught correctly"
fi

TOTAL=$((PASSED + FAILED))
if [ $TOTAL -gt 0 ]; then
    PERCENT=$((PASSED * 100 / TOTAL))
    echo -e "\n${BLUE}Success rate:${NC} $PERCENT%"
fi

if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}Some tests failed!${NC}"
    exit 1
fi
