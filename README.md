# HoodiePM

A modern, cross-platform password generator and manager written in Python that creates secure, random passwords with an elegant user interface and securely stores your credentials. HoodiePM not only generates strong passwords but also provides a fully-featured password management system to securely store and organize all your login information.

<!-- Add a screenshot once available -->
<!-- ![HoodiePM Screenshot](screenshot.png) -->

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Python Versions](https://img.shields.io/badge/python-3.6%2B-blue)

## Executables

Pre-built executables are available in the [Releases](https://github.com/Spacii-AN/Hoddie-password-manager/releases) section of this repository:
- Windows: `HoodiePM-Windows.exe`
- Mac: `HoodiePM-macOS`
- Linux: `HoodiePM-Linux`

### Building Executables Yourself

To build the executable yourself, you'll need Python 3.6+ and PyInstaller:

```bash
# Install required dependencies
pip install -r requirements.txt

# Build the executable
# On Windows:
pyinstaller --onefile --windowed --name="HoodiePM" hoodie_generator_gui.py

# On Mac/Linux:
pyinstaller --onefile --windowed --name="HoodiePM" hoodie_generator_gui.py
```

The executable will be created in the `dist` directory.

## Features

### Password Generation
- Generate passwords with fixed length or variable length range (6-24 characters)
- Customize character sets (uppercase, lowercase, numbers, special characters)
- Real-time password statistics display
- Multithreaded processing for faster generation of multiple passwords
- Generate all possible passwords and save to a text file
- Copy generated passwords to clipboard with visual feedback
- Automatic clipboard clearing for enhanced security

### Password Management
- Secure storage of passwords using industry-standard encryption
- Categorize and organize passwords by website, application, or service
- Search functionality to quickly find stored credentials
- Password strength analysis and recommendations
- Secure password backup and restore capabilities
- Auto-lock feature after period of inactivity
- Master password protection for accessing your password vault

### User Interface
- Cross-platform compatibility (Windows, macOS, Linux)
- Modern, responsive UI with light and dark themes
- Intuitive tabbed interface for different functions
- Customizable settings and preferences

## Requirements

- Python 3.6 or higher
- Pillow library (for application icon and image handling)
- cryptography and bcrypt (for secure password storage and hashing)
- SQLite3 (included with Python) for database functionality
- pysqlcipher3 (optional, for enhanced database encryption)
- ttkthemes (for additional UI themes)

## Installation

### Option 1: Use pre-built executables
1. Download the appropriate executable for your platform from [Releases](https://github.com/Spacii-AN/Hoddie-password-manager/releases)
2. Run the executable directly - no installation required!
3. For Linux users, you may need to make the file executable with: `chmod +x HoodiePM-Linux`

### Option 2: Run from source
1. Clone this repository:
   ```bash
   git clone https://github.com/Spacii-AN/Hoddie-password-manager.git
   cd Hoddie-password-manager
   ```
2. Make sure you have Python 3.6+ installed on your system
3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the application:
   ```bash
   python hoodie_generator_gui.py
   ```

## Usage

### Graphical User Interface

```
python hoodie_generator_gui.py
```

This launches the GUI version with all options available through an easy-to-use interface.

### Password Manager

To use the password manager functionality:

1. Launch the application and navigate to the "Password Manager" tab
2. Create a master password when prompted (first-time use)
3. Add your credentials by clicking the "Add New" button
4. Enter the website/service name, username, and password
5. Optionally add notes or additional details
6. Your passwords are automatically encrypted and stored securely
7. To retrieve a password, select it from the list and click "View"
8. Use the search function to quickly find specific credentials



## Security Notes

- Always use a password with sufficient length for security-critical applications
- The default options produce passwords with good entropy
- Your password database is encrypted with industry-standard algorithms
- The master password is never stored - only a secure hash is saved
- Backups are automatically encrypted with the same security as the main database
- The application can be configured to lock after a period of inactivity
- The standalone executables contain all required dependencies and don't require Python to be installed

## Performance Notes

- When generating multiple passwords, the program automatically uses multithreading
- By default, it uses all available CPU cores for maximum performance
- You can specify the number of threads with the `-t` option

## GUI Features

### Password Generator Interface
- Modern, responsive interface with light and dark theme support
- Tabbed interface for different password generation and management tasks
- Password length options:
  - Fixed length with slider for easy adjustment
  - Variable length range (min-max) for flexible passwords (except in "Generate All" tab)
- Character set checkboxes for customization
- Copy to clipboard functionality with visual feedback
- Always-visible password statistics for better security awareness
- Batch password generation with save-to-file option
- Progress tracking for generation of all possible passwords
- Warnings about large file sizes when generating all passwords
- Time and size estimation for large password generation
- Professional splash screen at startup

### Password Manager Interface
- Dedicated password management tab with secure storage
- Encrypted database for storing all credentials
- Master password protection with secure hashing
- Add, edit, and delete password entries
- Organize passwords by categories or tags
- Password history tracking for each entry
- Auto-lock after inactivity for additional security
- Search and filter capabilities for stored credentials
- Password strength assessment with visual indicators
- Import and export functionality (encrypted format)
- Automatic backup creation to prevent data loss

## Generating All Possible Passwords

- The `--all` option allows you to generate every possible password for a given length and character set
- You must specify an output file with `-o` or `--output` when using `--all`
- **Note**: The `--all` option does not support length ranges (`-r`), only fixed length passwords (`-l`)
- **Warning**: This can create extremely large files for even moderate password lengths
  - 4 characters with all character types: ~16 million passwords
  - 6 characters with all character types: ~56 billion passwords
- The program will warn you if the estimated file size exceeds 1GB
- Use `--force` to override the safety check for large password sets

## Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -am 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

Areas where contributions are especially welcome:
- Enhanced encryption algorithms for the password database
- Additional import/export formats
- Password breach checking
- UI improvements and accessibility features
- Auto-fill functionality for browsers

## Development Setup

To set up for development:

1. Clone the repository:
   ```bash
   git clone https://github.com/Spacii-AN/Hoddie-password-manager.git
   cd Hoddie-password-manager
   ```

2. Install development dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the GUI version:
   ```bash
   python hoodie_generator_gui.py
   ```
   
   Or use the provided launcher script on Linux/Mac:
   ```bash
   ./launch_gui.sh
   ```



## License

This project is open source and available under the [MIT License](LICENSE).