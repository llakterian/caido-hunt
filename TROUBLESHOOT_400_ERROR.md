# Troubleshooting 400 Bad Request Error

## What the 400 Error Means

A 400 Bad Request error typically means:
- The browser is sending data the server doesn't understand
- Missing required fields in the request
- Invalid JSON format
- CORS issue (Cross-Origin Resource Sharing)

## Quick Fixes

### Fix 1: Check Browser Console

1. Open the Real-Time GUI
2. Press F12 to open Developer Tools
3. Go to "Console" tab
4. Click "Start Scan"
5. Look for detailed error messages

### Fix 2: Check Server Terminal

Look at the terminal where you launched the GUI for error messages like:
```
ERROR: Invalid JSON data
ERROR: Target URL is required
ERROR: Server error: ...
```

### Fix 3: Test with Simple GUI Instead

If Real-Time GUI has issues, use the simple GUI:

```bash
cd ~/Desktop/caido-hunt
source caido-env/bin/activate
python simple_gui.py --port 5001
```

### Fix 4: Check Your Target URL

Make sure your target URL:
- ✅ Starts with http:// or https://
- ✅ Is a valid domain
- ✅ Doesn't have spaces or special characters

Examples:
- ✅ http://example.com
- ✅ https://testphp.vulnweb.com
- ❌ example.com (missing protocol - but will be auto-fixed)
- ❌ https://example .com (has space)

### Fix 5: Manual Test

Test the API directly:

```bash
curl -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"http://example.com","threads":5,"delay":1.0,"timeout":30}'
```

Should return:
```json
{"success":true,"message":"Scan started","target":"http://example.com"}
```

### Fix 6: Check Dependencies

```bash
cd ~/Desktop/caido-hunt
source caido-env/bin/activate
pip install --upgrade flask requests beautifulsoup4
```

### Fix 7: Try Different Port

Maybe port 5000 is already in use:

```bash
python realtime_gui.py --port 5001
```

Then access: http://127.0.0.1:5001

## Common Causes & Solutions

### Issue: "Content-Type" Header Missing

**Solution**: Already fixed in latest version. Update your files:
```bash
cd ~/Desktop/caido-hunt
git pull origin main
```

### Issue: Browser Caching Old Version

**Solution**: Hard refresh the page
- Chrome/Firefox: Ctrl + Shift + R
- Or clear browser cache

### Issue: Virtual Environment Not Activated

**Solution**: The launcher script handles this, but if running manually:
```bash
source caido-env/bin/activate
python realtime_gui.py
```

### Issue: Flask Not Installed

**Solution**:
```bash
pip install flask
```

## Debug Mode

Run in debug mode to see detailed errors:

1. Edit `realtime_gui.py`
2. Find the line: `self.app.run(host=self.host, port=self.port, debug=False, threaded=True)`
3. Change `debug=False` to `debug=True`
4. Restart the GUI

## Still Having Issues?

### Collect Debug Info

```bash
# Check Python version
python --version

# Check Flask is installed
python -c "import flask; print(flask.__version__)"

# Check file exists
ls -la realtime_gui.py

# Test simple server
python -m http.server 8000
# If this works, Python is fine
```

### Use Simple GUI as Fallback

The simple_gui.py doesn't use Server-Sent Events and might work better:

```bash
python simple_gui.py --port 5000
```

### Contact Support

If none of these work, report the issue with:
1. Error message from browser console (F12)
2. Error message from terminal
3. Python version (`python --version`)
4. OS version

Email: llakterian@gmail.com
GitHub: https://github.com/llakterian/caido-hunt/issues

## Quick Check Command

Run this to diagnose:

```bash
cd ~/Desktop/caido-hunt
source caido-env/bin/activate
python -c "
import flask
import requests
print('✅ Flask version:', flask.__version__)
print('✅ Requests version:', requests.__version__)
print('✅ Python OK!')
" && echo "✅ All dependencies OK"
```

