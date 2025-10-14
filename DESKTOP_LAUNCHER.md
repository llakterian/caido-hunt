# Caido Hunt - Desktop Launcher Guide

Quick setup guide for creating a desktop icon to launch Caido Hunt with one click.

**Author**: Llakterian (llakterian@gmail.com)  
**Repository**: https://github.com/llakterian/caido-hunt

---

## 🎯 Overview

The desktop launcher automatically:
- ✅ Activates the Python virtual environment
- ✅ Checks and installs dependencies
- ✅ Launches the Caido Hunt GUI
- ✅ Opens your browser to http://127.0.0.1:5000

---

## 🐧 Linux Setup (Ubuntu/Debian/ParrotOS)

### Quick Setup (Recommended)

Run the automated setup script:

```bash
cd ~/Desktop/caido-hunt
./setup_desktop_icon.sh
```

This will:
1. Create a desktop icon
2. Add Caido Hunt to your application menu
3. Set up quick launch shortcuts

### Manual Setup

If the automated script doesn't work:

1. **Make launcher executable**:
   ```bash
   chmod +x launch_caido_hunt.sh
   ```

2. **Copy to Desktop**:
   ```bash
   cp caido-hunt.desktop ~/Desktop/
   chmod +x ~/Desktop/caido-hunt.desktop
   ```

3. **Mark as trusted** (Ubuntu/GNOME):
   ```bash
   gio set ~/Desktop/caido-hunt.desktop metadata::trusted true
   ```

4. **Add to application menu**:
   ```bash
   cp caido-hunt.desktop ~/.local/share/applications/
   update-desktop-database ~/.local/share/applications/
   ```

---

## 🪟 Windows Setup

### Method 1: Batch File (Simple)

1. **Double-click** `launch_caido_hunt.bat`
   - This will start the GUI in a command window
   - Keep the window open while using the scanner

2. **Create Desktop Shortcut** (Optional):
   - Right-click `launch_caido_hunt.bat`
   - Select "Send to" → "Desktop (create shortcut)"
   - Rename to "Caido Hunt Scanner"

### Method 2: Create Windows Shortcut

1. **Right-click** on Desktop → "New" → "Shortcut"

2. **Location**: Enter:
   ```
   C:\Windows\System32\cmd.exe /k "cd /d C:\path\to\caido-hunt && launch_caido_hunt.bat"
   ```
   (Replace `C:\path\to\caido-hunt` with your actual path)

3. **Name**: `Caido Hunt Scanner`

4. **Change Icon** (Optional):
   - Right-click shortcut → Properties
   - Click "Change Icon"
   - Browse to `%SystemRoot%\System32\imageres.dll`
   - Choose a security-related icon

---

## 🚀 Usage

### Starting Caido Hunt

**Linux**:
- Double-click the desktop icon, OR
- Search for "Caido Hunt" in application menu, OR
- Run `./start.sh` from terminal

**Windows**:
- Double-click the desktop shortcut or `launch_caido_hunt.bat`

### What Happens

1. Terminal/Command window opens
2. Virtual environment activates automatically
3. Dependencies are checked (installed if needed)
4. GUI launches at http://127.0.0.1:5000
5. Browser opens automatically (or open manually)

### Using the GUI

1. **Enter target URL** (e.g., `https://testphp.vulnweb.com`)
2. **Configure scan settings**:
   - Threads: 5-20 (default: 10)
   - Delay: 0.5-2.0 seconds (default: 1.0)
   - Timeout: 30-60 seconds (default: 30)
3. **Click "Start Scan"**
4. **Watch real-time results**
5. **Export** findings as JSON or CSV

### Stopping the Scanner

- **GUI**: Click the stop button or close browser tab
- **Terminal**: Press `Ctrl+C` to stop the server
- **Windows**: Close the command window

---

## 🎨 Desktop Icon Options (Linux)

Right-click the desktop icon for additional options:

1. **Launch Simple GUI** (Default) - Beginner-friendly interface
2. **Launch Advanced GUI** - Real-time updates with SocketIO
3. **Launch CLI Scanner** - Command-line interface with help

---

## 🛠️ Troubleshooting

### Icon doesn't appear on desktop

**Linux**:
```bash
# Check if file exists
ls -la ~/Desktop/caido-hunt.desktop

# Make executable
chmod +x ~/Desktop/caido-hunt.desktop

# Mark as trusted (GNOME)
gio set ~/Desktop/caido-hunt.desktop metadata::trusted true
```

**Windows**:
- Ensure `launch_caido_hunt.bat` is in the project directory
- Try creating shortcut manually (see Method 2 above)

### "Virtual environment not found" error

```bash
# Create virtual environment manually
cd ~/Desktop/caido-hunt  # or your caido-hunt directory
python3 -m venv caido-env
source caido-env/bin/activate  # Linux
# caido-env\Scripts\activate  # Windows
pip install -r requirements.txt
```

### "Module not found" errors

Dependencies not installed. Run:

```bash
cd ~/Desktop/caido-hunt
source caido-env/bin/activate  # Linux
# caido-env\Scripts\activate  # Windows
pip install -r requirements.txt
```

### GUI doesn't open in browser

Manually open your browser and go to:
```
http://127.0.0.1:5000
```

Or try a different port:
```bash
python simple_gui.py --port 5001
```

### Port already in use

Change the port in `launch_caido_hunt.sh` (Linux) or `launch_caido_hunt.bat` (Windows):

Replace `--port 5000` with `--port 5001` (or any other available port)

### Permission denied (Linux)

```bash
chmod +x launch_caido_hunt.sh
chmod +x setup_desktop_icon.sh
```

---

## 📂 File Locations

### Linux

- **Desktop Icon**: `~/Desktop/caido-hunt.desktop`
- **App Menu**: `~/.local/share/applications/caido-hunt.desktop`
- **Launcher Script**: `~/Desktop/caido-hunt/launch_caido_hunt.sh`
- **Quick Launch**: `~/Desktop/caido-hunt/start.sh`

### Windows

- **Desktop Shortcut**: `Desktop\Caido Hunt Scanner.lnk`
- **Launcher Batch**: `caido-hunt\launch_caido_hunt.bat`

---

## 🔧 Customization

### Change Default Port

Edit the launcher script:

**Linux** (`launch_caido_hunt.sh`):
```bash
# Change this line:
python simple_gui.py --port 5000
# To:
python simple_gui.py --port 8080
```

**Windows** (`launch_caido_hunt.bat`):
```batch
REM Change this line:
python simple_gui.py --port 5000
REM To:
python simple_gui.py --port 8080
```

### Use Advanced GUI Instead

**Linux** (`launch_caido_hunt.sh`):
```bash
# Replace:
python simple_gui.py --port 5000
# With:
python unified_gui.py --port 5000
```

**Windows** (`launch_caido_hunt.bat`):
```batch
REM Replace:
python simple_gui.py --port 5000
REM With:
python unified_gui.py --port 5000
```

### Change Terminal Colors (Linux)

Edit color codes in `launch_caido_hunt.sh`:
```bash
GREEN='\033[0;32m'   # Green text
BLUE='\033[0;34m'    # Blue text
YELLOW='\033[1;33m'  # Yellow text
RED='\033[0;31m'     # Red text
```

---

## 🚦 Quick Start Cheat Sheet

### First Time Setup

```bash
# Linux
cd ~/Desktop/caido-hunt
./setup_desktop_icon.sh

# Windows
cd C:\path\to\caido-hunt
double-click launch_caido_hunt.bat
```

### Daily Use

1. **Double-click** desktop icon
2. **Wait** for GUI to load
3. **Enter** target URL
4. **Click** "Start Scan"
5. **Export** results when done

---

## 📞 Support

### Need Help?

- **Documentation**: See [README.md](README.md) and [QUICKSTART.md](QUICKSTART.md)
- **Issues**: https://github.com/llakterian/caido-hunt/issues
- **Email**: llakterian@gmail.com

### Report Bugs

If the launcher doesn't work:

1. Check prerequisites (Python 3.8+, pip)
2. Run launcher from terminal to see error messages
3. Try manual setup instructions above
4. Report issue with error log to GitHub

---

## ✅ Verification

After setup, verify everything works:

```bash
# Linux - Test launcher
cd ~/Desktop/caido-hunt
./launch_caido_hunt.sh

# Windows - Test launcher
cd C:\path\to\caido-hunt
launch_caido_hunt.bat
```

You should see:
1. ✅ Virtual environment activation message
2. ✅ "Starting Caido Hunt GUI..." message
3. ✅ Browser opening to http://127.0.0.1:5000
4. ✅ Caido Hunt interface loading

---

## 🎓 Alternative Launch Methods

### Command Line (Advanced Users)

```bash
# Activate venv manually
cd ~/Desktop/caido-hunt
source caido-env/bin/activate  # Linux
# caido-env\Scripts\activate  # Windows

# Run scanner directly
python ultimate_scanner_challenge.py https://target.com --verbose

# Or launch GUI
python simple_gui.py --port 5000
```

### Create Custom Keyboard Shortcut (Linux)

1. Go to **Settings** → **Keyboard** → **Custom Shortcuts**
2. Add new shortcut:
   - Name: `Launch Caido Hunt`
   - Command: `/home/c0bw3b/Desktop/caido-hunt/launch_caido_hunt.sh`
   - Shortcut: `Ctrl+Alt+C` (or your preference)

---

## 🌟 Tips for Best Experience

1. **Pin to Taskbar** (Windows) or **Favorites** (Linux) for quick access
2. **Keep terminal open** while scanning (shows status/errors)
3. **Check logs** in `reports/` directory if issues occur
4. **Update regularly**: `git pull origin main` in project directory

---

## 📜 License

MIT License - See [LICENSE](LICENSE) file

---

## 🙏 Credits

**Built by Llakterian**  
📧 llakterian@gmail.com  
🔗 https://github.com/llakterian/caido-hunt

---

*For security vulnerabilities, please see [SECURITY.md](SECURITY.md)*  
*For contribution guidelines, please see [CONTRIBUTING.md](CONTRIBUTING.md)*

---

**Last Updated**: January 14, 2024  
**Version**: 2.0.0