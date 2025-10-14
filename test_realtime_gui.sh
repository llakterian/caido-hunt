#!/bin/bash
echo "Testing Real-Time GUI..."
echo ""
echo "Starting server with debug output..."
echo ""

cd ~/Desktop/caido-hunt
source caido-env/bin/activate 2>/dev/null

# Run with explicit output
python realtime_gui.py --port 5000 2>&1 | tee /tmp/gui_debug.log
