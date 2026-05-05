#!/bin/bash
# NIDS — Automated Setup Script
# Sets up the full project environment from scratch

set -e  # exit on any error

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║     NIDS — Network Intrusion Detection System        ║"
echo "║     Automated Setup Script                           ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Check Python ─────────────────────────────────────────────────
echo -e "${YELLOW}[1/6] Checking Python version...${NC}"
python3 --version || { echo -e "${RED}Python 3 not found. Install it first.${NC}"; exit 1; }

# ── Check system deps ─────────────────────────────────────────────
echo -e "${YELLOW}[2/6] Installing system dependencies...${NC}"
sudo apt update -qq
sudo apt install -y python3-venv python3-pip libpcap-dev net-tools nmap -qq
echo -e "${GREEN}  ✓ System dependencies installed${NC}"

# ── Virtual environment ───────────────────────────────────────────
echo -e "${YELLOW}[3/6] Setting up virtual environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}  ✓ Virtual environment created${NC}"
else
    echo -e "${GREEN}  ✓ Virtual environment already exists${NC}"
fi

source venv/bin/activate

# ── Python dependencies ───────────────────────────────────────────
echo -e "${YELLOW}[4/6] Installing Python dependencies...${NC}"
pip install -q --upgrade pip
pip install -q -r requirements.txt
echo -e "${GREEN}  ✓ Python dependencies installed${NC}"

# ── Directory structure ───────────────────────────────────────────
echo -e "${YELLOW}[5/6] Creating directory structure...${NC}"
mkdir -p data/raw data/processed data/reports
mkdir -p models logs captured_data/flows docs/images
echo -e "${GREEN}  ✓ Directories created${NC}"

# ── Find network interface ────────────────────────────────────────
echo -e "${YELLOW}[6/6] Detecting network interface...${NC}"
INTERFACE=$(ip link show | grep -E "^[0-9]+: (wl|en|eth)" | \
            grep "UP" | head -1 | awk -F': ' '{print $2}' | cut -d'@' -f1)

if [ -z "$INTERFACE" ]; then
    INTERFACE=$(ip link show | grep -E "^[0-9]+: " | \
                grep -v "lo:" | head -1 | awk -F': ' '{print $2}')
fi

echo -e "${GREEN}  ✓ Detected interface: ${INTERFACE}${NC}"

# Update settings.py with detected interface
sed -i "s/INTERFACE.*=.*\".*\"/INTERFACE      = \"${INTERFACE}\"/" config/settings.py
echo -e "${GREEN}  ✓ Updated config/settings.py with interface: ${INTERFACE}${NC}"

# ── Done ──────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Setup complete! Here's what to do next:             ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  1. Download CICIDS-2017 dataset from:"
echo "     https://www.unb.ca/cic/datasets/ids-2017.html"
echo "     Place CSVs in: data/raw/MachineLearningCVE/"
echo ""
echo "  2. Preprocess the dataset:"
echo "     python3 main.py --mode preprocess"
echo ""
echo "  3. Train the models:"
echo "     python3 main.py --mode train"
echo ""
echo "  4. Launch the dashboard:"
echo "     sudo venv/bin/python3 main.py --mode dashboard"
echo "     Open: http://localhost:5001"
echo ""
echo "  5. Run the demo (in a second terminal):"
echo "     python3 scripts/demo_attack.py"
echo ""
