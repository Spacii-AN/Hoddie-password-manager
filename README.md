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

### Windows Setup

#### Option 1: Using the Executable (Recommended)
1. Download the latest `HoodiePM-Windows.exe` from [Releases](https://github.com/Spacii-AN/Hoddie-password-manager/releases)
2. Double-click the executable to run - no installation required!
3. If you get a Windows security warning, click "More info" and then "Run anyway"

#### Option 2: Running from Source
1. Install Python 3.6 or higher from [python.org](https://www.python.org/downloads/)
   - Make sure to check "Add Python to PATH" during installation
2. Open Command Prompt or PowerShell and clone the repository:
   ```powershell
   git clone https://github.com/Spacii-AN/Hoddie-password-manager.git
   cd Hoddie-password-manager
   ```
3. Create and activate a virtual environment:
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate
   ```
4. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
5. Run the application:
   ```powershell
   python src/gui/main_window.py
   ```

### macOS Setup

#### Option 1: Using the App Bundle (Recommended)
1. Download the latest `HoodiePM-Mac.dmg` from [Releases](https://github.com/Spacii-AN/Hoddie-password-manager/releases)
2. Double-click the .dmg file and drag HoodiePM to your Applications folder
3. Open HoodiePM from your Applications folder
4. If you get a security warning, go to System Preferences > Security & Privacy and click "Open Anyway"

#### Option 2: Running from Source
1. Install Python 3.6 or higher:
   ```bash
   # Using Homebrew
   brew install python
   ```
2. Open Terminal and clone the repository:
   ```bash
   git clone https://github.com/Spacii-AN/Hoddie-password-manager.git
   cd Hoddie-password-manager
   ```
3. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Run the application:
   ```bash
   python src/gui/main_window.py
   ```

### Linux Setup

#### Option 1: Using the AppImage (Recommended)
1. Download the latest `HoodiePM-Linux.AppImage` from [Releases](https://github.com/Spacii-AN/Hoddie-password-manager/releases)
2. Make the AppImage executable:
   ```bash
   chmod +x HoodiePM-Linux.AppImage
   ```
3. Run the AppImage:
   ```bash
   ./HoodiePM-Linux.AppImage
   ```

#### Option 2: Running from Source
1. Install Python 3.6 or higher:
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install python3 python3-pip python3-venv

   # Fedora
   sudo dnf install python3 python3-pip

   # Arch Linux
   sudo pacman -S python python-pip
   ```
2. Open Terminal and clone the repository:
   ```bash
   git clone https://github.com/Spacii-AN/Hoddie-password-manager.git
   cd Hoddie-password-manager
   ```
3. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Run the application:
   ```bash
   python src/gui/main_window.py
   ```

### Common Issues and Solutions

#### Windows
- If you get a "python not found" error, make sure Python is added to your PATH
- If you get a "pip not found" error, try using `python -m pip` instead of just `pip`

#### macOS
- If you get a "permission denied" error when running the AppImage, run:
  ```bash
  chmod +x HoodiePM-Mac.AppImage
  ```
- If you get a security warning, you may need to allow the app in System Preferences > Security & Privacy

#### Linux
- If you get a "python3 not found" error, install Python 3 using your distribution's package manager
- If you get a "pip not found" error, install pip using:
  ```bash
  # Ubuntu/Debian
  sudo apt install python3-pip

  # Fedora
  sudo dnf install python3-pip

  # Arch Linux
  sudo pacman -S python-pip
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

## Security Notes

- All password hashing and key derivation use scrypt with strong parameters
- All data is encrypted at rest using AES-256-GCM
- The master password is never stored or logged
- No plaintext secrets are ever written to disk or logs
- Clipboard is securely cleared after use
- Backups are automatically encrypted with the same security as the main database
- The application can be configured to lock after a period of inactivity
- The standalone executables contain all required dependencies and don't require Python to be installed

## Security Best Practices
- Always use a strong, unique master password
- Regularly update your application to receive security updates
- Never share your master password or encrypted database files
- Make regular encrypted backups of your password database

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
- ttkbootstrap (for modern GUI)
- SQLite3 (included with Python) for database functionality

## Security Notes

- All password hashing and key derivation use scrypt with strong parameters
- All data is encrypted at rest using AES-256-GCM
- The master password is never stored or logged
- No plaintext secrets are ever written to disk or logs
- Clipboard is securely cleared after use
- Backups are automatically encrypted with the same security as the main database
- The application can be configured to lock after a period of inactivity
- The standalone executables contain all required dependencies and don't require Python to be installed

## Security Best Practices
- Always use a strong, unique master password
- Regularly update your application to receive security updates
- Never share your master password or encrypted database files
- Make regular encrypted backups of your password database

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