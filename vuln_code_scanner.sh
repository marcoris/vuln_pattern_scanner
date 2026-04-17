#!/bin/bash

set -euo pipefail

# -----------------------------
# Colors
# -----------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# -----------------------------
# Banner
# -----------------------------
echo -e "${CYAN}"
cat << "EOF"
========================================
   Vulnerability Pattern Scanner
   Lightweight RG-based Security Tool
========================================
EOF
echo -e "${NC}"

# -----------------------------
# Configuration
# -----------------------------
PATTERN_FILE="vulnpattern.txt"
EXCLUDE_FILE="vulnwhitelist.txt"
OUTPUT_FILE="vuln_output.txt"
CSV_FILE="vuln_output.csv"
CURRENT_DATE=$(date +%d.%m.%Y)

TARGET="${1:-}"

# -----------------------------
# Validation
# -----------------------------
if [[ -z "$TARGET" ]]; then
    echo -e "${RED}[!] Usage: $0 <file_or_directory>${NC}"
    exit 1
fi

if [[ ! -e "$TARGET" ]]; then
    echo -e "${RED}[!] Target not found: $TARGET${NC}"
    exit 1
fi

if [[ ! -f "$PATTERN_FILE" ]]; then
    echo -e "${RED}[!] Pattern file missing: $PATTERN_FILE${NC}"
    exit 1
fi

# -----------------------------
# Build exclude args
# -----------------------------
EXCLUDE_ARGS=()
if [[ -f "$EXCLUDE_FILE" ]]; then
    while IFS= read -r pattern; do
        [[ -z "$pattern" ]] && continue
        EXCLUDE_ARGS+=(--glob "!$pattern")
    done < "$EXCLUDE_FILE"
fi

# -----------------------------
# Start scan
# -----------------------------
echo -e "${BLUE}[*] Starting scan on:${NC} $TARGET"

rg -ni --no-heading --color=never \
   -f "$PATTERN_FILE" "$TARGET" \
   "${EXCLUDE_ARGS[@]}" \
   > "$OUTPUT_FILE"

ROWCOUNT=$(wc -l < "$OUTPUT_FILE")

echo -e "${GREEN}[+] Scan completed.${NC} Results: ${YELLOW}$ROWCOUNT${NC}"

# -----------------------------
# CSV generation
# -----------------------------
if [[ "$ROWCOUNT" -ne 0 ]]; then
    echo -e "${BLUE}[*] Generating CSV report...${NC}"

    echo "Date,Date of Assessment,Status,File,Row,Possible Vulnerability" > "$CSV_FILE"

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        file="${line%%:*}"
        rest="${line#*:}"
        row="${rest%%:*}"
        code="${rest#*:}"

        file="${file#../}"
        code="$(sed 's/^[[:space:]]*//' <<< "$code")"
        code="${code//\"/\"\"}"

        printf '%s,,,%s,%s,"%s"\n' \
            "$CURRENT_DATE" "$file" "$row" "$code" >> "$CSV_FILE"

    done < "$OUTPUT_FILE"

    echo -e "${GREEN}[+] CSV created:${NC} $CSV_FILE"
else
    echo -e "${YELLOW}[-] No findings detected. Skipping CSV generation.${NC}"
fi
