@echo off
setlocal enabledelayedexpansion

:: Launch Script for Hoodie Password Manager
:: This script launches the GUI application with all necessary dependencies

:: Get the directory where the script is located
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%.."

:: Add the project root to PYTHONPATH
set "PYTHONPATH=%PROJECT_ROOT%;%PYTHONPATH%"

:: Function to print colored messages
call :print_message "Checking Python installation..."

:: Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [31mError: Python is not installed. Please install Python to run this application.[0m
    exit /b 1
)

:: Check Python version
for /f "tokens=2" %%I in ('python --version 2^>^&1') do set "PYTHON_VERSION=%%I"
if "%PYTHON_VERSION:~0,3%" LSS "3.8" (
    echo [31mError: Python 3.8 or higher is required. Current version: %PYTHON_VERSION%[0m
    exit /b 1
)

:: Check if pip is installed
python -m pip --version >nul 2>&1
if errorlevel 1 (
    echo [31mError: pip is not installed. Please install pip to manage Python packages.[0m
    exit /b 1
)

:: Check and install required packages
call :print_message "Checking required packages..."
python -c "
import sys
import pkg_resources

required = {'ttkbootstrap', 'cryptography', 'pillow'}
installed = {pkg.key for pkg in pkg_resources.working_set}
missing = required - installed

if missing:
    print(f'Installing missing packages: {missing}')
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', *missing])
"
if errorlevel 1 (
    echo [31mError: Failed to check/install required packages[0m
    exit /b 1
)

:: Run the application
call :print_message "Starting Hoodie Password Manager..."
cd /d "%PROJECT_ROOT%"
python -m src.gui.main_window
if errorlevel 1 (
    echo [31mError: Application failed to start[0m
    exit /b 1
)

exit /b 0

:print_message
echo [34m%~1[0m
exit /b 0 