@echo off
echo ============================================================
echo   🔍 Phish-Detect Automatic Setup Script (Windows) 🔍
echo ============================================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in your system PATH.
    echo Please install Python 3.12+ and try again.
    pause
    exit /b
)

:: 1. Create Virtual Environment
echo [1/3] Creating Python Virtual Environment (venv)...
python -m venv venv
if %errorlevel% neq 0 (
    echo [ERROR] Failed to create virtual environment.
    pause
    exit /b
)

:: 2. Install Dependencies
echo [2/3] Installing Python Dependencies from requirements.txt...
call venv\Scripts\activate.bat
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b
)

:: 3. Provision Playwright Browser Binaries
echo [3/3] Installing Playwright Chromium browser binaries...
python -m playwright install chromium
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install Playwright browser binaries.
    pause
    exit /b
)

echo.
echo ============================================================
echo   🎉 Setup Complete successfully! 🎉
echo ============================================================
echo.
echo to start the interactive scanner, run:
echo   venv\Scripts\python.exe src\main.py --interactive
echo.
pause
