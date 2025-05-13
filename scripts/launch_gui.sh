#!/bin/bash

# Launch Script for Hoodie Password Manager
# This script launches the GUI application with all necessary dependencies

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_ROOT/venv"

# Add the project root to PYTHONPATH
export PYTHONPATH="$PROJECT_ROOT:$PYTHONPATH"

# Function to print colored messages
print_message() {
    echo -e "\033[1;34m$1\033[0m"  # Blue color for messages
}

print_error() {
    echo -e "\033[1;31mError: $1\033[0m"  # Red color for errors
}

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed. Please install Python 3 to run this application."
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
if (( $(echo "$PYTHON_VERSION < 3.8" | bc -l) )); then
    print_error "Python 3.8 or higher is required. Current version: $PYTHON_VERSION"
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    print_error "pip3 is not installed. Please install pip3 to manage Python packages."
    exit 1
fi

# Create and activate virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    print_message "Creating virtual environment..."
    python3 -m venv "$VENV_DIR" || {
        print_error "Failed to create virtual environment"
        exit 1
    }
fi

# Activate virtual environment
print_message "Activating virtual environment..."
source "$VENV_DIR/bin/activate" || {
    print_error "Failed to activate virtual environment"
    exit 1
}

# Upgrade pip
print_message "Upgrading pip..."
python -m pip install --upgrade pip || {
    print_error "Failed to upgrade pip"
    exit 1
}

# Install required packages from requirements.txt
print_message "Installing required packages..."
python -m pip install -r "$PROJECT_ROOT/requirements.txt" || {
    print_error "Failed to install required packages"
    exit 1
}

# Create logs directory if it doesn't exist
mkdir -p "$PROJECT_ROOT/logs"

# Run the application with logging
print_message "Starting Hoodie Password Manager..."
cd "$PROJECT_ROOT"
python -m src.gui.main_window > "logs/app_$(date +%Y%m%d_%H%M%S).log" 2>&1 || {
    print_error "Application failed to start. Check logs for details."
    exit 1
}

# Deactivate virtual environment
deactivate 