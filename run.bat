@echo off
setlocal enabledelayedexpansion
title TLScope - TLS Certificate & HTTPS Security Analysis Tool

echo ===============================================================================
echo     TLScope: TLS Certificate & HTTPS Security Analysis Platform
echo     Academic Cryptography & Network Security Audit Engine
echo ===============================================================================
echo.

:: 1. Check Python installation
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python was not found in your system PATH!
    echo Please install Python 3.10+ from https://www.python.org/
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

:: 2. Create virtual environment if missing
if not exist ".venv" (
    echo [*] Creating virtual environment (.venv)...
    python -m venv .venv
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created.
)

:: 3. Activate virtual environment
call .venv\Scripts\activate.bat

:: 4. Install dependencies
echo [*] Checking and installing dependencies from requirements.txt...
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)
echo [OK] Dependencies verified.

:: 5. Launch application
echo.
echo ===============================================================================
echo   TLScope is starting up at http://127.0.0.1:5000
echo   Press Ctrl+C to stop the server when finished.
echo ===============================================================================
echo.

:: Optionally launch browser
start http://127.0.0.1:5000

python app.py

pause
