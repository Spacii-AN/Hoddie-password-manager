# Hoodie

A modern, cross-platform password generator and manager written in Python that creates secure, random passwords with an elegant user interface and securely stores your credentials.

<!-- Add a screenshot once available -->
<!-- ![Password Generator Screenshot](screenshot.png) -->

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Python Versions](https://img.shields.io/badge/python-3.6%2B-blue)

## Executables

Pre-built executables are available in the [Releases](https://github.com/USERNAME/Hoodie/releases) section of this repository:
- Windows: `Hoodie-Windows.zip`
- Mac: `Hoodie-Mac.zip`
- Linux: `Hoodie-Linux.zip`

### Building Executables Yourself

To build the executable yourself, you'll need Python 3.6+ and PyInstaller:

```bash
# Install required dependencies
pip install -r requirements.txt

# Build the executable
# On Windows:
pyinstaller --onefile --windowed --name="Hoodie" hoodie_generator_gui.py

# On Mac/Linux:
pyinstaller --onefile --windowed --name="Hoodie" hoodie_generator_gui.py
```

The executable will be created in the `dist` directory.

## Features

- Generate passwords with fixed length or variable length range (6-24 characters)
- Customize character sets (uppercase, lowercase, numbers, special characters)
- Secure password manager with encrypted storage
- Cross-platform compatibility (Windows, macOS, Linux)
- Graphical user interface with modern design
- Modern, responsive UI with light and dark themes
- Real-time password statistics display
- Multithreaded processing for faster generation of multiple passwords
- Generate all possible passwords and save to a text file
- Copy generated passwords to clipboard with visual feedback
- Automatic clipboard clearing for enhanced security

## Requirements

- Python 3.6 or higher
- Pillow library (for application icon and image handling)
- cryptography and bcrypt (for secure password storage)
- SQLite3 (included with Python)

## Installation

### Option 1: Use pre-built executables
1. Download the appropriate executable for your platform from [Releases](https://github.com/USERNAME/Hoodie/releases)
2. Extract the ZIP file
3. Run the executable directly - no installation required!

### Option 2: Run from source
1. Clone this repository:
   ```bash
   git clone https://github.com/USERNAME/Hoodie.git
   cd Hoodie
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



## Security Notes

- Always use a password with sufficient length for security-critical applications
- The default options produce passwords with good entropy
- Consider using a password manager to store generated passwords
- The standalone executables contain all required dependencies and don't require Python to be installed

## Performance Notes

- When generating multiple passwords, the program automatically uses multithreading
- By default, it uses all available CPU cores for maximum performance
- You can specify the number of threads with the `-t` option

## GUI Features

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
- Secure password management:
  - Encrypted storage of username, password, and website/account info
  - Password history tracking
  - Auto-lock after inactivity for additional security
  - Search and filter capabilities for stored credentials
  - Password strength assessment

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

## Development Setup

To set up for development:

1. Clone the repository:
   ```bash
   git clone https://github.com/USERNAME/Hoodie.git
   cd Hoodie
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