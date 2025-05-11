#!/bin/bash

# Launch Script for Hoodie Password Generator with Password Manager
# This script launches the updated GUI that includes the password manager

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Change to the script directory
cd "$SCRIPT_DIR"

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed or not in your PATH."
    echo "Please install Python 3 and try again."
    exit 1
fi

# Check if required packages are installed
if ! python3 -c "import tkinter" &> /dev/null; then
    echo "Warning: tkinter module not found. GUI may not work properly."
fi

# Define colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting Hoodie Password Generator with Password Manager${NC}"

# Check if we're using the new or old version
if [ -f "hoodie_generator_gui_new.py" ]; then
    echo -e "${YELLOW}Using new GUI version with Password Manager${NC}"
    GUI_FILE="hoodie_generator_gui_new.py"
else
    echo -e "${YELLOW}New GUI file not found, using standard version${NC}"
    GUI_FILE="hoodie_generator_gui.py"
fi

# Try to run the GUI application
python3 $GUI_FILE

# Exit with the exit code of the Python script
exit_code=$?

# If there was an error, provide more information
if [ $exit_code -ne 0 ]; then
    echo ""
    echo -e "${RED}The application exited with an error (code $exit_code).${NC}"
    echo "You might need to install the required dependencies:"
    echo "  pip3 install -r requirements.txt"
    
    # Add additional dependencies for the password manager
    echo ""
    echo "For password manager functionality, you may also need:"
    echo "  pip3 install bcrypt pysqlcipher3"
fi

exit $exit_code