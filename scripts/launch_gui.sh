#!/bin/bash

# Launch Script for Hoodie Password Generator with Password Manager
# This script launches the updated GUI that includes the password manager

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Add the project root to PYTHONPATH
export PYTHONPATH="$PROJECT_ROOT:$PYTHONPATH"

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    exit 1
fi

# Check if required packages are installed
echo "Checking required packages..."
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
    echo "Error: Failed to check/install required packages"
    exit 1
}

# Run the application
echo "Starting Hoodie Password Manager..."
cd "$PROJECT_ROOT"
python3 -m src.gui.main_window