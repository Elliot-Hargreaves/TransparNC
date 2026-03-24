#!/bin/bash
# Master test runner for all TransparNC container-based test suites.
#
# Discovers and runs every test script under tests/container/, collects
# exit codes, and prints a summary table at the end.
#
# Usage: ./run_all_tests.sh
#
# Each test suite script is expected to exit 0 on success and non-zero
# on failure. This wrapper always runs every suite (does not bail on
# first failure) so the summary is complete.

set -o pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---------------------------------------------------------------------------
# Colour helpers (disabled when stdout is not a terminal)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    GREEN='' RED='' YELLOW='' BOLD='' RESET=''
fi

# ---------------------------------------------------------------------------
# Discover test suites
# ---------------------------------------------------------------------------
# Each run_*.sh script directly inside tests/container/ is treated as a
# top-level test suite.  Sub-directory scripts (e.g. ice/*.sh) are invoked
# by their parent suite runner and are NOT executed independently here.
SUITES=()
for script in "$PROJECT_DIR"/tests/container/run_*.sh; do
    [ -f "$script" ] && SUITES+=("$script")
done

if [ ${#SUITES[@]} -eq 0 ]; then
    echo "No test suites found under tests/container/run_*.sh"
    exit 1
fi

# ---------------------------------------------------------------------------
# Run suites and collect results
# ---------------------------------------------------------------------------
declare -A RESULTS   # suite name -> "PASS" | "FAIL"
declare -a ORDER     # preserve insertion order for the summary
OVERALL=0

echo -e "${BOLD}========================================${RESET}"
echo -e "${BOLD}  TransparNC — Full Test Suite Runner${RESET}"
echo -e "${BOLD}========================================${RESET}"
echo ""
echo "Found ${#SUITES[@]} test suite(s):"
for s in "${SUITES[@]}"; do
    echo "  - $(basename "$s")"
done
echo ""

for suite in "${SUITES[@]}"; do
    name="$(basename "$suite" .sh)"
    echo -e "${BOLD}────────────────────────────────────────${RESET}"
    echo -e "${BOLD}▶ Running: ${name}${RESET}"
    echo -e "${BOLD}────────────────────────────────────────${RESET}"

    if bash "$suite"; then
        RESULTS["$name"]="PASS"
    else
        RESULTS["$name"]="FAIL"
        OVERALL=1
    fi
    ORDER+=("$name")
    echo ""
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
PASSED=0
FAILED=0
for name in "${ORDER[@]}"; do
    [ "${RESULTS[$name]}" = "PASS" ] && ((PASSED++)) || ((FAILED++))
done

echo -e "${BOLD}========================================${RESET}"
echo -e "${BOLD}  Test Summary${RESET}"
echo -e "${BOLD}========================================${RESET}"
echo ""
printf "  %-40s %s\n" "Suite" "Result"
printf "  %-40s %s\n" "----------------------------------------" "------"
for name in "${ORDER[@]}"; do
    if [ "${RESULTS[$name]}" = "PASS" ]; then
        printf "  %-40s ${GREEN}PASS${RESET}\n" "$name"
    else
        printf "  %-40s ${RED}FAIL${RESET}\n" "$name"
    fi
done
echo ""
echo -e "  Total: ${#ORDER[@]}  |  ${GREEN}Passed: ${PASSED}${RESET}  |  ${RED}Failed: ${FAILED}${RESET}"
echo ""

if [ $OVERALL -eq 0 ]; then
    echo -e "${GREEN}${BOLD}✔ All test suites passed.${RESET}"
else
    echo -e "${RED}${BOLD}✘ Some test suites failed.${RESET}"
fi

exit $OVERALL
