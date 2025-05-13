@echo off
setlocal enabledelayedexpansion

:: Launch Script for Hoodie Password Manager
:: This script launches the GUI application with all necessary dependencies

:: Get the directory where the script is located
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%.."
set "VENV_DIR=%PROJECT_ROOT%\venv"

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
for /f "tokens=1,2 delims=." %%a in ("!PYTHON_VERSION!") do (
    set "MAJOR=%%a"
    set "MINOR=%%b"
)
if !MAJOR! LSS 3 (
    echo [31mError: Python 3.8 or higher is required. Current version: !PYTHON_VERSION![0m
    exit /b 1
)
if !MAJOR! EQU 3 (
    if !MINOR! LSS 8 (
        echo [31mError: Python 3.8 or higher is required. Current version: !PYTHON_VERSION![0m
        exit /b 1
    )
)

:: Check if pip is installed
python -m pip --version >nul 2>&1
if errorlevel 1 (
    echo [31mError: pip is not installed. Please install pip to manage Python packages.[0m
    exit /b 1
)

:: Create and activate virtual environment if it doesn't exist
if not exist "%VENV_DIR%" (
    call :print_message "Creating virtual environment..."
    python -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo [31mError: Failed to create virtual environment[0m
        exit /b 1
    )
)

:: Activate virtual environment
call :print_message "Activating virtual environment..."
call "%VENV_DIR%\Scripts\activate.bat"
if errorlevel 1 (
    echo [31mError: Failed to activate virtual environment[0m
    exit /b 1
)

:: Upgrade pip
call :print_message "Upgrading pip..."
python -m pip install --upgrade pip
if errorlevel 1 (
    echo [31mError: Failed to upgrade pip[0m
    exit /b 1
)

:: Install required packages from requirements.txt
call :print_message "Installing required packages..."
python -m pip install -r "%PROJECT_ROOT%\requirements.txt"
if errorlevel 1 (
    echo [31mError: Failed to install required packages[0m
    exit /b 1
)

:: Create logs directory if it doesn't exist
if not exist "%PROJECT_ROOT%\logs" mkdir "%PROJECT_ROOT%\logs"

:: Run the application with logging
call :print_message "Starting Hoodie Password Manager..."
cd /d "%PROJECT_ROOT%"
python -m src.gui.main_window > "logs\app_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.log" 2>&1
if errorlevel 1 (
    echo [31mError: Application failed to start. Check logs for details.[0m
    exit /b 1
)

:: Deactivate virtual environment
call deactivate

exit /b 0

:print_message
echo [34m%~1[0m
exit /b 0 