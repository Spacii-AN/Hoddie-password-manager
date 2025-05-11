# HoodiePM - Secure Password Manager

A modern, cross-platform password generator and manager written in Python that creates secure, random passwords with an elegant user interface and securely stores your credentials. HoodiePM not only generates strong passwords but also provides a fully-featured password management system to securely store and organize all your login information.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Python Versions](https://img.shields.io/badge/python-3.6%2B-blue)

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
- Multi-user support with individual password databases
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
   ./scripts/launch_gui.sh
   ```

## Project Structure

```
HoodiePM/
├── src/                      # Source code directory
│   ├── core/                # Core functionality
│   │   ├── password_manager.py
│   │   └── user_manager.py
│   ├── gui/                 # GUI-related code
│   │   ├── main_window.py
│   │   ├── theme.py
│   │   └── app_icon.py
│   └── utils/              # Utility functions
│       └── password_generator.py
├── data/                   # Data storage
│   ├── users/             # User data
│   ├── password_databases/ # Password databases
│   └── backups/           # Backup files
├── scripts/               # Executable scripts
├── tests/                # Test files
├── docs/                 # Documentation
└── requirements.txt      # Python dependencies
```

## Security Features

- PBKDF2HMAC for key derivation
- Fernet encryption for password storage
- Secure password hashing
- Automatic clipboard clearing
- Encrypted database storage
- Master password protection
- Auto-lock functionality
- Secure backup and restore

## Development

### Setting up the development environment

1. Clone the repository:
   ```bash
   git clone https://github.com/Spacii-AN/Hoddie-password-manager.git
   cd Hoddie-password-manager
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install development dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run tests:
   ```bash
   pytest
   ```

### Building executables

To build the executable yourself, you'll need Python 3.6+ and PyInstaller:

```bash
# Install required dependencies
pip install -r requirements.txt

# Build the executable
# On Windows:
pyinstaller --onefile --windowed --name="HoodiePM" src/gui/main_window.py

# On Mac/Linux:
pyinstaller --onefile --windowed --name="HoodiePM" src/gui/main_window.py
```

The executable will be created in the `dist` directory.

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

## License

This project is open source and available under the [MIT License](LICENSE).

## Acknowledgments

- [ttkbootstrap](https://github.com/israel-dryer/ttkbootstrap) for the modern UI components
- [cryptography](https://github.com/pyca/cryptography) for the encryption functionality
- [Pillow](https://github.com/python-pillow/Pillow) for image handling 