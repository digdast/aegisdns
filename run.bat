@echo off
chcp 65001 >nul
title AegisDNS - Recursive DoH Resolver & Threat Defense
echo ========================================================
echo   🛡️  AegisDNS - Recursive DoH Resolver & Threat Engine
echo   Port 53 (UDP/TCP) ^| Web UI & DoH: http://localhost:5380
echo ========================================================
echo.

:: Ensure Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not found in PATH. Please install Python 3.10+.
    pause
    exit /b 1
)

:: Install requirements if needed
echo [*] Checking dependencies...
pip install -r "%~dp0requirements.txt" --quiet

:: Launch AegisDNS
echo [*] Launching AegisDNS core server...
set PYTHONPATH=%~dp0
python -m aegisdns.main

pause
