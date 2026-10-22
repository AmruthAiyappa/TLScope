#!/usr/bin/env bash
# ==============================================================================
# TLScope - TLS Certificate & HTTPS Security Analysis Tool
# Automated Setup & Launch Script for macOS and Linux
# ==============================================================================

set -e

echo "==============================================================================="
echo "    TLScope: TLS Certificate & HTTPS Security Analysis Platform"
echo "    Academic Cryptography & Network Security Audit Engine"
echo "==============================================================================="
echo ""

# 1. Check Python installation
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD=python3
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD=python
else
    echo "[ERROR] Python 3 was not found! Please install Python 3.10+ using your package manager (brew/apt/dnf)."
    exit 1
fi

# 2. Create virtual environment if missing
if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment (.venv)..."
    $PYTHON_CMD -m venv .venv
    echo "[OK] Virtual environment created."
fi

# 3. Activate virtual environment
source .venv/bin/activate

# 4. Install dependencies
echo "[*] Checking and installing dependencies from requirements.txt..."
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
echo "[OK] Dependencies verified."

# 5. Launch application
echo ""
echo "==============================================================================="
echo "  TLScope is starting up at http://127.0.0.1:5000"
echo "  Press Ctrl+C to stop the server when finished."
echo "==============================================================================="
echo ""

# Try to open the default web browser in the background
if command -v xdg-open >/dev/null 2>&1; then
    (sleep 1 && xdg-open http://127.0.0.1:5000) >/dev/null 2>&1 &
elif command -v open >/dev/null 2>&1; then
    (sleep 1 && open http://127.0.0.1:5000) >/dev/null 2>&1 &
fi

python app.py
