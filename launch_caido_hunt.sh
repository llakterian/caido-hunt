#!/bin/bash
################################################################################
# Caido Hunt - Desktop Launcher
# Author: Llakterian (llakterian@gmail.com)
# Repository: https://github.com/llakterian/caido-hunt
################################################################################

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

clear
echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}       ${GREEN}🎯 Caido Hunt - Bug Bounty Scanner${NC}         ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}       ${YELLOW}Built by Llakterian${NC}                        ${BLUE}║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if virtual environment exists
if [ ! -d "caido-env" ]; then
    echo -e "${RED}❌ Virtual environment not found!${NC}"
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv caido-env

    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to create virtual environment!${NC}"
        echo "Press Enter to exit..."
        read
        exit 1
    fi

    echo -e "${GREEN}✅ Virtual environment created${NC}"
fi

# Activate virtual environment
echo -e "${YELLOW}🔄 Activating virtual environment...${NC}"
source caido-env/bin/activate

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to activate virtual environment!${NC}"
    echo "Press Enter to exit..."
    read
    exit 1
fi

echo -e "${GREEN}✅ Virtual environment activated${NC}"

# Check if dependencies are installed
echo -e "${YELLOW}🔍 Checking dependencies...${NC}"
if ! python -c "import flask" 2>/dev/null; then
    echo -e "${YELLOW}📦 Installing dependencies...${NC}"
    pip install -r requirements.txt

    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Failed to install dependencies!${NC}"
        echo "Press Enter to exit..."
        read
        exit 1
    fi

    echo -e "${GREEN}✅ Dependencies installed${NC}"
else
    echo -e "${GREEN}✅ Dependencies already installed${NC}"
fi

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}🚀 Starting Caido Hunt Real-Time GUI...${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}📍 Real-Time GUI with live terminal output${NC}"
echo -e "${YELLOW}📍 GUI will open at: ${GREEN}http://127.0.0.1:5000${NC}"
echo -e "${YELLOW}📍 Press ${RED}Ctrl+C${YELLOW} to stop the scanner${NC}"
echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo ""

# Start the Real-Time GUI with live terminal output
python realtime_gui.py --port 5000

# When GUI is stopped
echo ""
echo -e "${YELLOW}👋 Caido Hunt stopped${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo ""
echo "Press Enter to close this window..."
read
