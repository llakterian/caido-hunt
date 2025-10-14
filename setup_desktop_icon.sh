#!/bin/bash
################################################################################
# Caido Hunt - Desktop Icon Setup Script
# Author: Llakterian (llakterian@gmail.com)
# Repository: https://github.com/llakterian/caido-hunt
#
# This script creates a desktop launcher for Caido Hunt
################################################################################

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

clear
echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}  ${GREEN}Caido Hunt - Desktop Icon Setup${NC}                ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}  ${YELLOW}Built by Llakterian${NC}                            ${BLUE}║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

# Get current directory
CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo -e "${YELLOW}📍 Installation directory: ${NC}$CURRENT_DIR"
echo ""

# Make launcher script executable
echo -e "${YELLOW}🔧 Making launcher script executable...${NC}"
chmod +x "$CURRENT_DIR/launch_caido_hunt.sh"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Launcher script is now executable${NC}"
else
    echo -e "${RED}❌ Failed to make launcher executable${NC}"
    exit 1
fi

# Create desktop directory if it doesn't exist
DESKTOP_DIR="$HOME/Desktop"
if [ ! -d "$DESKTOP_DIR" ]; then
    echo -e "${YELLOW}Creating Desktop directory...${NC}"
    mkdir -p "$DESKTOP_DIR"
fi

# Update the .desktop file with correct path
echo -e "${YELLOW}🔧 Updating desktop entry with current path...${NC}"
cat > "$CURRENT_DIR/caido-hunt.desktop" << EOF
[Desktop Entry]
Version=2.0
Type=Application
Name=Caido Hunt Scanner
GenericName=Bug Bounty Scanner
Comment=Advanced vulnerability scanner for bug bounty hunting - Built by Llakterian
Exec=gnome-terminal -- bash -c "cd $CURRENT_DIR && ./launch_caido_hunt.sh; exec bash"
Icon=security-high
Terminal=false
Categories=Development;Security;Network;
Keywords=security;scanner;vulnerability;bugbounty;pentesting;
StartupNotify=true
Path=$CURRENT_DIR
Actions=CLI;SimpleGUI;AdvancedGUI;

[Desktop Action CLI]
Name=Launch CLI Scanner
Exec=gnome-terminal -- bash -c "cd $CURRENT_DIR && source caido-env/bin/activate && python ultimate_scanner_challenge.py --help && echo '' && echo 'Ready to scan! Usage: python ultimate_scanner_challenge.py <target>' && exec bash"

[Desktop Action SimpleGUI]
Name=Launch Simple GUI
Exec=gnome-terminal -- bash -c "cd $CURRENT_DIR && ./launch_caido_hunt.sh; exec bash"

[Desktop Action AdvancedGUI]
Name=Launch Advanced GUI
Exec=gnome-terminal -- bash -c "cd $CURRENT_DIR && source caido-env/bin/activate && python unified_gui.py; exec bash"
EOF

echo -e "${GREEN}✅ Desktop entry updated${NC}"

# Copy to desktop
echo -e "${YELLOW}📋 Copying launcher to Desktop...${NC}"
cp "$CURRENT_DIR/caido-hunt.desktop" "$DESKTOP_DIR/"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Launcher copied to Desktop${NC}"
else
    echo -e "${RED}❌ Failed to copy launcher to Desktop${NC}"
fi

# Make desktop file executable
chmod +x "$DESKTOP_DIR/caido-hunt.desktop"

# Try to mark as trusted (for Ubuntu/GNOME)
if command -v gio &> /dev/null; then
    echo -e "${YELLOW}🔐 Marking desktop launcher as trusted...${NC}"
    gio set "$DESKTOP_DIR/caido-hunt.desktop" metadata::trusted true 2>/dev/null
    echo -e "${GREEN}✅ Desktop launcher marked as trusted${NC}"
fi

# Copy to applications directory (for app menu)
APPS_DIR="$HOME/.local/share/applications"
if [ ! -d "$APPS_DIR" ]; then
    mkdir -p "$APPS_DIR"
fi

echo -e "${YELLOW}📋 Installing to application menu...${NC}"
cp "$CURRENT_DIR/caido-hunt.desktop" "$APPS_DIR/"
chmod +x "$APPS_DIR/caido-hunt.desktop"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Added to application menu${NC}"
fi

# Update desktop database
if command -v update-desktop-database &> /dev/null; then
    echo -e "${YELLOW}🔄 Updating desktop database...${NC}"
    update-desktop-database "$APPS_DIR" 2>/dev/null
    echo -e "${GREEN}✅ Desktop database updated${NC}"
fi

# Create a quick launch script in the project directory
echo -e "${YELLOW}📝 Creating quick launch command...${NC}"
cat > "$CURRENT_DIR/start.sh" << 'EOF'
#!/bin/bash
# Quick launcher for Caido Hunt
cd "$(dirname "$0")"
./launch_caido_hunt.sh
EOF

chmod +x "$CURRENT_DIR/start.sh"
echo -e "${GREEN}✅ Quick launch script created: ./start.sh${NC}"

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ SETUP COMPLETE!${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}🎉 Desktop icon has been created!${NC}"
echo ""
echo -e "${YELLOW}You can now launch Caido Hunt in 3 ways:${NC}"
echo ""
echo -e "  ${BLUE}1.${NC} Double-click the ${GREEN}'Caido Hunt Scanner'${NC} icon on your desktop"
echo -e "  ${BLUE}2.${NC} Search for ${GREEN}'Caido Hunt'${NC} in your application menu"
echo -e "  ${BLUE}3.${NC} Run ${GREEN}'./start.sh'${NC} from this directory"
echo ""
echo -e "${YELLOW}📝 Right-click the desktop icon for additional options:${NC}"
echo -e "  • Launch CLI Scanner"
echo -e "  • Launch Simple GUI (default)"
echo -e "  • Launch Advanced GUI"
echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}📍 Icon location:${NC} $DESKTOP_DIR/caido-hunt.desktop"
echo -e "${YELLOW}📍 App menu location:${NC} $APPS_DIR/caido-hunt.desktop"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}Built by Llakterian${NC} | ${BLUE}llakterian@gmail.com${NC}"
echo -e "${BLUE}Repository:${NC} https://github.com/llakterian/caido-hunt"
echo ""

# Check if running in GUI environment
if [ -n "$DISPLAY" ]; then
    echo -e "${YELLOW}Would you like to test the launcher now? (y/n)${NC}"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}🚀 Launching Caido Hunt...${NC}"
        sleep 1
        ./launch_caido_hunt.sh
    fi
fi

echo ""
echo "Press Enter to exit..."
read
