#!/bin/bash
# launcher.sh
# Made by SAM

echo -e "\033[96m\033[1m"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║          iDRAC CVE Hunter - Dual Engine Launcher               ║"
echo "║                     Coded by SAM                                 ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "\033[0m"

# Install dependencies
echo "[*] Installing Python dependencies..."
pip3 install -q -r requirements.txt 2>/dev/null

# Install Go dependencies
echo "[*] Installing Go dependencies..."
go get github.com/mattn/go-sqlite3 2>/dev/null

# Build Go checker
echo "[*] Building Go checker..."
go build -o idrac_checker idrac_checker.go

# Run both simultaneously
echo -e "\n\033[92m[+] Starting Scraper (Python) & Checker (Go)...\033[0m\n"

python3 idrac_scraper.py &
SCRAPER_PID=$!

sleep 5  # Let scraper populate some data

./idrac_checker &
CHECKER_PID=$!

echo -e "\n\033[93m[!] Press Ctrl+C to stop both engines\033[0m"
echo -e "\033[93m[!] Scraper PID: $SCRAPER_PID | Checker PID: $CHECKER_PID\033[0m\n"

wait
