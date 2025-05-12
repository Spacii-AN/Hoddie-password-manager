#!/bin/bash

# Launch Script for Hoodie Password Manager
# This script launches the GUI application with all necessary dependencies

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

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

# Check and install required packages
print_message "Checking required packages..."
python3 -c "
import sys
import pkg_resources

required = {'ttkbootstrap', 'cryptography', 'pillow'}
installed = {pkg.key for pkg in pkg_resources.working_set}
missing = required - installed

if missing:
    print(f'Installing missing packages: {missing}')
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', *missing])
" || {
    print_error "Failed to check/install required packages"
    exit 1
}

# Run the application
print_message "Starting Hoodie Password Manager..."
cd "$PROJECT_ROOT"
python3 -m src.gui.main_window || {
    print_error "Application failed to start"
    exit 1
} 