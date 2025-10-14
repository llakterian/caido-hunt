@echo off
REM ################################################################################
REM Caido Hunt - Windows Desktop Launcher
REM Author: Llakterian (llakterian@gmail.com)
REM Repository: https://github.com/llakterian/caido-hunt
REM ################################################################################

setlocal enabledelayedexpansion

REM Change to the script's directory
cd /d "%~dp0"

cls
echo ================================================================
echo        Caido Hunt - Bug Bounty Scanner
echo        Built by Llakterian
echo ================================================================
echo.

REM Check if virtual environment exists
if not exist "caido-env" (
    echo [ERROR] Virtual environment not found!
    echo.
    echo Creating virtual environment...
    python -m venv caido-env

    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment!
        echo.
        echo Please ensure Python 3.8+ is installed and in your PATH.
        pause
        exit /b 1
    )

    echo [SUCCESS] Virtual environment created
    echo.
)

REM Activate virtual environment
echo [INFO] Activating virtual environment...
call caido-env\Scripts\activate.bat

if errorlevel 1 (
    echo [ERROR] Failed to activate virtual environment!
    pause
    exit /b 1
)

echo [SUCCESS] Virtual environment activated
echo.

REM Check if dependencies are installed
echo [INFO] Checking dependencies...
python -c "import flask" 2>nul

if errorlevel 1 (
    echo [INFO] Installing dependencies...
    echo.
    pip install -r requirements.txt

    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies!
        pause
        exit /b 1
    )

    echo.
    echo [SUCCESS] Dependencies installed
) else (
    echo [SUCCESS] Dependencies already installed
)

echo.
echo ================================================================
echo Starting Caido Hunt GUI...
echo ================================================================
echo.
echo GUI will open at: http://127.0.0.1:5000
echo Press Ctrl+C to stop the scanner
echo.
echo ================================================================
echo.

REM Start the GUI
python simple_gui.py --port 5000

REM When GUI is stopped
echo.
echo.
echo Caido Hunt stopped
echo ================================================================
echo.
pause
