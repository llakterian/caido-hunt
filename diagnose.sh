#!/bin/bash

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  Caido Hunt - 400 Error Diagnostics                           ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

cd ~/Desktop/caido-hunt

# Check venv
echo "1. Checking virtual environment..."
if [ -d "caido-env" ]; then
    echo "   ✅ Virtual environment exists"
else
    echo "   ❌ Virtual environment NOT found!"
    exit 1
fi

# Activate and check Flask
echo ""
echo "2. Checking Flask installation..."
source caido-env/bin/activate
python -c "import flask" 2>/dev/null && echo "   ✅ Flask is installed" || echo "   ❌ Flask NOT installed!"

# Check if port is available
echo ""
echo "3. Checking if port 5000 is available..."
if lsof -Pi :5000 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "   ❌ Port 5000 is already in use!"
    echo "   Try: python realtime_gui.py --port 5001"
else
    echo "   ✅ Port 5000 is available"
fi

# Check files
echo ""
echo "4. Checking scanner files..."
[ -f "realtime_gui.py" ] && echo "   ✅ realtime_gui.py exists" || echo "   ❌ realtime_gui.py NOT found!"
[ -f "ultimate_scanner_challenge.py" ] && echo "   ✅ ultimate_scanner_challenge.py exists" || echo "   ❌ Scanner NOT found!"

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  Recommended Actions:                                          ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "If you see ❌ above, try:"
echo ""
echo "  • For missing Flask: pip install flask"
echo "  • For port in use: python realtime_gui.py --port 5001"
echo "  • For missing files: Check you're in caido-hunt directory"
echo ""
echo "To test the GUI, run:"
echo "  ./start.sh"
echo ""

