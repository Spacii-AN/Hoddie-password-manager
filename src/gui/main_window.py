import os
import string
import sys
import time
import threading
import datetime
import random
import logging
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext
import ttkbootstrap as tb
from ttkbootstrap.constants import *

# Import local modules
from ..utils.password_generator import (
    generate_password,
    generate_passwords_in_parallel,
    estimate_password_count,
    calculate_password_strength
)
from .theme import ThemeManager
from ..core.password_manager import create_manager_tab
from ..core.user_manager import get_user_manager

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Check if we're importing this as a module or running directly
IMPORTED_HAS_CALLBACK = False  # Flag if we're imported and have callback support

class PasswordGeneratorApp(tb.Window):
    """Main application class for Password Generator GUI"""

    def __init__(self):
        super().__init__()

        # Configure the main window
        self.title("Hoodie Password Manager")
        self.geometry("800x650")
        self.minsize(600, 500)  # Set minimum window size

        # Set icon if available
        try:
            icon_path = Path(__file__).parent / 'app_icon.ico'  # Changed from .py to .ico
            if icon_path.exists():
                self.iconbitmap(str(icon_path))
            else:
                logger.warning(f"Icon file not found at {icon_path}")
        except Exception as e:
            logger.warning(f"Could not load application icon: {e}")

        # Theme variables
        self.theme_mode = tb.StringVar(value="light")
        self.theme_button = None  # Initialize theme button variable

        # Variables for password generation options
        self.length_var = tb.IntVar(value=12)
        self.min_length_var = tb.IntVar(value=8)
        self.max_length_var = tb.IntVar(value=16)
        self.length_type_var = tb.StringVar(value="fixed")
        self.use_uppercase_var = tb.BooleanVar(value=True)
        self.use_lowercase_var = tb.BooleanVar(value=True)
        self.use_numbers_var = tb.BooleanVar(value=True)
        self.use_special_var = tb.BooleanVar(value=True)
        self.password_count_var = tb.IntVar(value=1)
        self.output_file_var = tb.StringVar()
        self.batch_output_file_var = tb.StringVar()
        self.single_output_file_var = tb.StringVar()

        # Initialize display widgets
        self.password_display = None
        self.batch_display = None
        self.stats_text = None
        self.batch_stats_label = None
        self.progress_var = tb.DoubleVar(value=0)
        self.status_display = None

        # For tracking scheduled callbacks
        self.after_ids = []

        # Initialize theme manager
        try:
            self.theme_manager = ThemeManager(self)
        except Exception as e:
            logger.error(f"Failed to initialize theme manager: {e}")
            messagebox.showerror("Error", "Failed to initialize theme manager")
            raise

        # Create widgets
        try:
            self.create_widgets()
        except Exception as e:
            logger.error(f"Failed to create widgets: {e}")
            messagebox.showerror("Error", "Failed to create application interface")
            raise

        # Apply theme after widgets are created
        try:
            self.apply_theme()
        except Exception as e:
            logger.error(f"Failed to apply theme: {e}")
            messagebox.showerror("Error", "Failed to apply theme")
            raise

        # Set up generation thread
        self.generation_thread = None
        self.stop_generation = False

        # Bind cleanup function to window close
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

        # Seed the random number generator
        random.seed(os.urandom(16))

        # Log startup information
        logger.info("Starting Hoodie Password Manager GUI")
        logger.info(f"Python version: {sys.version}")
        logger.info(f"Working directory: {os.getcwd()}")

    def create_widgets(self):
        """Create the main application widgets"""
        # Create notebook for tabs
        self.notebook = tb.Notebook(self)
        self.notebook.pack(fill=tb.BOTH, expand=True, padx=10, pady=5)

        # Create theme button
        self.theme_button = tb.Button(
            self,
            text="Dark",
            style="link.TButton",
            command=self.toggle_theme
        )
        self.theme_button.pack(side=tb.TOP, anchor=tb.E, padx=10, pady=5)

        # Create tabs
        self.create_generator_tab()
        self.create_multiple_generator_tab()  # Add the new multiple generator tab
        self.create_password_manager_tab()
        self.create_about_tab()

    def create_generator_tab(self):
        """Create the main generator tab"""
        generator_frame = tb.Frame(self.notebook)
        self.notebook.add(generator_frame, text="Generate Password")

        # Options frame
        options_frame = tb.LabelFrame(generator_frame, text="Password Options")
        options_frame.pack(fill=tb.BOTH, expand=True, padx=10, pady=10)

        # Password length options
        length_frame = tb.Frame(options_frame)
        length_frame.pack(fill=tb.X, padx=5, pady=5)

        # Fixed length only for single password
        tb.Label(length_frame, text="Password Length:").pack(side=tb.LEFT, padx=5)

        # Create a frame for the length controls
        length_control_frame = tb.Frame(length_frame)
        length_control_frame.pack(side=tb.LEFT, fill=tb.X, expand=True, padx=5)

        # Create buttons and entry
        def decrease_length():
            current = self.length_var.get()
            if current > 6:
                self.length_var.set(current - 1)

        def increase_length():
            current = self.length_var.get()
            if current < 24:
                self.length_var.set(current + 1)

        # Down button
        down_btn = tb.Button(
            length_control_frame,
            text="−",
            width=2,
            command=decrease_length
        )
        down_btn.pack(side=tb.LEFT)

        # Entry for length
        length_entry = tb.Entry(
            length_control_frame,
            textvariable=self.length_var,
            width=3,
            justify='center'
        )
        length_entry.pack(side=tb.LEFT, padx=2)

        # Up button
        up_btn = tb.Button(
            length_control_frame,
            text="+",
            width=2,
            command=increase_length
        )
        up_btn.pack(side=tb.LEFT)

        # Character type options
        char_frame = tb.Frame(options_frame)
        char_frame.pack(fill=tb.X, padx=5, pady=5)

        # Create a container for checkboxes that will wrap
        checkbox_container = tb.Frame(char_frame)
        checkbox_container.pack(fill=tb.X, expand=True)

        # Add checkboxes with proper spacing and wrapping
        tb.Checkbutton(
            checkbox_container,
            text="Uppercase (A-Z)",
            variable=self.use_uppercase_var
        ).pack(side=tb.LEFT, padx=5, expand=True)

        tb.Checkbutton(
            checkbox_container,
            text="Lowercase (a-z)",
            variable=self.use_lowercase_var
        ).pack(side=tb.LEFT, padx=5, expand=True)

        tb.Checkbutton(
            checkbox_container,
            text="Numbers (0-9)",
            variable=self.use_numbers_var
        ).pack(side=tb.LEFT, padx=5, expand=True)

        tb.Checkbutton(
            checkbox_container,
            text="Special (!@#$)",
            variable=self.use_special_var
        ).pack(side=tb.LEFT, padx=5, expand=True)

        # Generate button for single password
        generate_button = tb.Button(
            generator_frame,
            text="Generate Password",
            command=self.generate_single_password,
            style="Accent.TButton"
        )
        generate_button.pack(pady=10)

        # Password display
        result_frame = tb.LabelFrame(generator_frame, text="Generated Password")
        result_frame.pack(fill=tb.BOTH, expand=True, padx=10, pady=10)

        self.password_display = tb.Text(
            result_frame,
            height=1,
            font=("Courier", 12),
            wrap=tb.WORD
        )
        self.password_display.pack(fill=tb.BOTH, expand=True, padx=5, pady=5)

        # Add a copy button
        button_frame = tb.Frame(result_frame)
        button_frame.pack(fill=tb.X, padx=5, pady=5)

        tb.Button(
            button_frame,
            text="Copy to Clipboard",
            command=self.copy_to_clipboard
        ).pack(side=tb.LEFT, padx=5)

        tb.Button(
            button_frame,
            text="Save to File",
            command=self.save_single_password_to_file
        ).pack(side=tb.LEFT, padx=5)

        # Password statistics
        stats_frame = tb.LabelFrame(generator_frame, text="Password Statistics")
        stats_frame.pack(fill=tb.X, padx=10, pady=10)

        # Create a frame to hold the stats
        stats_container = tb.Frame(stats_frame)
        stats_container.pack(fill=tb.BOTH, expand=True, padx=5, pady=5)

        # Main stats label
        self.stats_text = tb.Label(
            stats_container,
            text="",
            wraplength=500
        )
        self.stats_text.pack(fill=tb.BOTH, expand=True)

        # Strength container
        strength_container = tb.Frame(stats_container)
        strength_container.pack(fill=tb.X)

        # Label for "Strength:"
        self.strength_text = tb.Label(
            strength_container,
            text=""
        )
        self.strength_text.pack(side=tb.LEFT)

        # Strength level label with styling
        self.strength_label = tb.Label(
            strength_container,
            text="",
            font=("Arial", 9, "bold")
        )
        self.strength_label.pack(side=tb.LEFT, padx=(5, 0))

    def create_multiple_generator_tab(self):
        """Create the multiple password generator tab"""
        multiple_frame = tb.Frame(self.notebook)
        self.notebook.add(multiple_frame, text="Generate Multiple")

        # Options frame
        options_frame = tb.LabelFrame(multiple_frame, text="Password Options")
        options_frame.pack(fill=tb.BOTH, expand=True, padx=10, pady=10)

        # Variables for this tab
        self.password_count_var = tb.IntVar(value=10)
        self.batch_output_file_var = tb.StringVar()

        # Length options frame
        length_frame = tb.Frame(options_frame)
        length_frame.pack(fill=tb.X, padx=5, pady=5)

        # Fixed length only for multiple passwords
        tb.Label(length_frame, text="Password Length:").pack(side=tb.LEFT, padx=5)

        # Create a frame for the length controls
        length_control_frame = tb.Frame(length_frame)
        length_control_frame.pack(side=tb.LEFT, fill=tb.X, expand=True, padx=5)

        # Create buttons and entry
        def decrease_length():
            current = self.length_var.get()
            if current > 6:
                self.length_var.set(current - 1)

        def increase_length():
            current = self.length_var.get()
            if current < 24:
                self.length_var.set(current + 1)

        # Down button
        down_btn = tb.Button(
            length_control_frame,
            text="−",
            width=2,
            command=decrease_length
        )
        down_btn.pack(side=tb.LEFT)

        # Entry for length
        length_entry = tb.Entry(
            length_control_frame,
            textvariable=self.length_var,
            width=3,
            justify='center'
        )
        length_entry.pack(side=tb.LEFT, padx=2)

        # Up button
        up_btn = tb.Button(
            length_control_frame,
            text="+",
            width=2,
            command=increase_length
        )
        up_btn.pack(side=tb.LEFT)

        # Password count options
        count_frame = tb.Frame(options_frame)
        count_frame.pack(fill=tb.X, padx=5, pady=5)

        tb.Label(count_frame, text="Number of Passwords:").pack(side=tb.LEFT, padx=5)

        # Create a frame for the count controls
        count_control_frame = tb.Frame(count_frame)
        count_control_frame.pack(side=tb.LEFT, fill=tb.X, expand=True, padx=5)

        # Create buttons and entry
        def decrease_count():
            current = self.password_count_var.get()
            if current > 1:
                self.password_count_var.set(current - 1)

        def decrease_count_by_ten():
            current = self.password_count_var.get()
            if current > 10:
                self.password_count_var.set(current - 10)
            else:
                self.password_count_var.set(1)

        def increase_count():
            current = self.password_count_var.get()
            if current < 1000:
                self.password_count_var.set(current + 1)

        def increase_count_by_ten():
            current = self.password_count_var.get()
            if current < 990:
                self.password_count_var.set(current + 10)
            else:
                self.password_count_var.set(1000)

        # Minus 10 button
        minus_ten_btn = tb.Button(
            count_control_frame,
            text="−10",
            width=4,
            command=decrease_count_by_ten
        )
        minus_ten_btn.pack(side=tb.LEFT)

        # Add a small gap
        tb.Frame(count_control_frame, width=5).pack(side=tb.LEFT)

        # Minus 1 button
        minus_btn = tb.Button(
            count_control_frame,
            text="−",
            width=2,
            command=decrease_count
        )
        minus_btn.pack(side=tb.LEFT)

        # Entry for count
        count_entry = tb.Entry(
            count_control_frame,
            textvariable=self.password_count_var,
            width=4,
            justify='center'
        )
        count_entry.pack(side=tb.LEFT, padx=2)

        # Plus 1 button
        plus_btn = tb.Button(
            count_control_frame,
            text="+",
            width=2,
            command=increase_count
        )
        plus_btn.pack(side=tb.LEFT)

        # Add a small gap
        tb.Frame(count_control_frame, width=5).pack(side=tb.LEFT)

        # Plus 10 button
        plus_ten_btn = tb.Button(
            count_control_frame,
            text="+10",
            width=4,
            command=increase_count_by_ten
        )
        plus_ten_btn.pack(side=tb.LEFT)

        # Character type options
        char_frame = tb.Frame(options_frame)
        char_frame.pack(fill=tb.X, padx=5, pady=5)

        # Create a container for checkboxes that will wrap
        checkbox_container = tb.Frame(char_frame)
        checkbox_container.pack(fill=tb.X, expand=True)

        # Add checkboxes with proper spacing and wrapping
        tb.Checkbutton(
            checkbox_container,
            text="Uppercase (A-Z)",
            variable=self.use_uppercase_var
        ).pack(side=tb.LEFT, padx=5, expand=True)

        tb.Checkbutton(
            checkbox_container,
            text="Lowercase (a-z)",
            variable=self.use_lowercase_var
        ).pack(side=tb.LEFT, padx=5, expand=True)

        tb.Checkbutton(
            checkbox_container,
            text="Numbers (0-9)",
            variable=self.use_numbers_var
        ).pack(side=tb.LEFT, padx=5, expand=True)

        tb.Checkbutton(
            checkbox_container,
            text="Special (!@#$)",
            variable=self.use_special_var
        ).pack(side=tb.LEFT, padx=5, expand=True)

        # Generate button
        generate_button = tb.Button(
            multiple_frame,
            text="Generate Passwords",
            command=self.generate_multiple_passwords,
            style="Accent.TButton"
        )
        generate_button.pack(pady=10)

        # Password display
        result_frame = tb.LabelFrame(multiple_frame, text="Generated Passwords")
        result_frame.pack(fill=tb.BOTH, expand=True, padx=10, pady=10)

        self.batch_display = tb.Text(
            result_frame,
            height=10,
            font=("Courier", 10),
            wrap=tb.WORD
        )
        self.batch_display.pack(fill=tb.BOTH, expand=True, padx=5, pady=5)

        # Add scrollbar to the text widget
        scrollbar = tb.Scrollbar(self.batch_display)
        scrollbar.pack(side=tb.RIGHT, fill=tb.Y)
        self.batch_display.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.batch_display.yview)

        # Button frame
        button_frame = tb.Frame(result_frame)
        button_frame.pack(fill=tb.X, padx=5, pady=5)

        tb.Button(
            button_frame,
            text="Copy All to Clipboard",
            command=lambda: self.copy_to_clipboard(self.batch_display)
        ).pack(side=tb.LEFT, padx=5)

        tb.Button(
            button_frame,
            text="Save to File",
            command=self.save_passwords_to_file
        ).pack(side=tb.LEFT, padx=5)

        # Batch statistics
        stats_frame = tb.LabelFrame(multiple_frame, text="Batch Statistics")
        stats_frame.pack(fill=tb.X, padx=10, pady=10)

        # Create a frame to hold the stats
        batch_stats_container = tb.Frame(stats_frame)
        batch_stats_container.pack(fill=tb.BOTH, expand=True, padx=5, pady=5)

        # Main stats label
        self.batch_stats_label = tb.Label(
            batch_stats_container,
            text="",
            wraplength=500
        )
        self.batch_stats_label.pack(fill=tb.BOTH, expand=True)

        # Strength container
        batch_strength_container = tb.Frame(batch_stats_container)
        batch_strength_container.pack(fill=tb.X)

        # Label for "Strength:"
        self.batch_strength_text = tb.Label(
            batch_strength_container,
            text=""
        )
        self.batch_strength_text.pack(side=tb.LEFT)

        # Strength level label with styling
        self.batch_strength_label = tb.Label(
            batch_strength_container,
            text="",
            font=("Arial", 9, "bold")
        )
        self.batch_strength_label.pack(side=tb.LEFT, padx=(5, 0))

    def create_password_manager_tab(self):
        """Create the password manager tab with multi-user support"""
        try:
            # Create the manager tab
            manager_tab = create_manager_tab(self.notebook)
            self.notebook.add(manager_tab, text="Password Manager")
            
        except Exception as e:
            logger.error(f"Error creating password manager tab: {e}")
            messagebox.showerror("Error", "Failed to create password manager tab")
            raise

    def create_about_tab(self):
        """Create the about tab with information about the application"""
        about_frame = tb.Frame(self.notebook)
        self.notebook.add(about_frame, text="About")

        # App title and version
        tb.Label(
            about_frame,
            text="Hoodie Password Manager",
            font=("Arial", 16, "bold")
        ).pack(pady=(20, 5))

        tb.Label(
            about_frame,
            text="v1.0"
        ).pack(pady=(0, 20))

        # Description
        tb.Label(
            about_frame,
            text="A secure password generator tool with multiple generation options",
            wraplength=500
        ).pack(pady=(0, 20))

        # Features frame
        features_frame = tb.LabelFrame(about_frame, text="Features")
        features_frame.pack(fill=tb.X, padx=20, pady=10)

        features_text = """
• Generate single, secure random passwords
• Generate batches of multiple passwords
• Multi-user Password Manager with encrypted storage
• Portable password databases with import/export
• Customizable password length and character sets
• Copy passwords to clipboard
• User accounts with secure login
• Light and dark themes
"""
        # Password Manager features with multi-user support
        tb.Label(
            features_frame,
            text=features_text,
            justify=tb.LEFT,
            wraplength=500
        ).pack(padx=10, pady=10, anchor=tb.W)

        # Credits
        credits_frame = tb.LabelFrame(about_frame, text="Credits")
        credits_frame.pack(fill=tb.X, padx=20, pady=10)

        tb.Label(
            credits_frame,
            text="Created with 💻 by Spacii-AN (GitHub: github.com/Spacii-AN)\nMulti-user Password Manager with Secure Encryption",
            wraplength=500
        ).pack(padx=10, pady=10)

    def center_window(self):
        """Center the window on the screen"""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

    def update_length_controls(self):
        """Update the state of length controls based on selected mode"""
        if self.length_type_var.get() == "fixed":
            self.fixed_length_spinbox.config(state="normal")
            self.min_length_spinbox.config(state="disabled")
            self.max_length_spinbox.config(state="disabled")
        else:  # range
            self.fixed_length_spinbox.config(state="disabled")
            self.min_length_spinbox.config(state="normal")
            self.max_length_spinbox.config(state="normal")

    def validate_length_range(self):
        """Ensure min_length <= max_length"""
        if self.min_length_var.get() > self.max_length_var.get():
            self.max_length_var.set(self.min_length_var.get())
        return True

    def generate_single_password(self):
        """Generate a single password and display it"""
        try:
            # Get password parameters
            length = self.length_var.get()
            use_uppercase = self.use_uppercase_var.get()
            use_lowercase = self.use_lowercase_var.get()
            use_numbers = self.use_numbers_var.get()
            use_special = self.use_special_var.get()

            # Validate at least one character type is selected
            if not (use_uppercase or use_lowercase or use_numbers or use_special):
                messagebox.showerror("Error", "At least one character type must be selected")
                return

            # Generate the password
            password = generate_password(
                length=length,
                use_uppercase=use_uppercase,
                use_lowercase=use_lowercase,
                use_numbers=use_numbers,
                use_special=use_special
            )

            # Display the password
            self.password_display.delete(1.0, tb.END)
            self.password_display.insert(tb.END, password)

            # Update statistics
            self.update_password_stats(password)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate password: {str(e)}")

    def update_password_stats(self, password):
        """Calculate and display statistics about the generated password"""
        # Get password characteristics
        length = len(password)
        uppercase_count = sum(1 for c in password if c in string.ascii_uppercase)
        lowercase_count = sum(1 for c in password if c in string.ascii_lowercase)
        number_count = sum(1 for c in password if c in string.digits)
        special_count = sum(1 for c in password if c in string.punctuation)

        # Calculate percentages
        total_chars = length
        uppercase_pct = (uppercase_count / total_chars) * 100 if total_chars > 0 else 0
        lowercase_pct = (lowercase_count / total_chars) * 100 if total_chars > 0 else 0
        number_pct = (number_count / total_chars) * 100 if total_chars > 0 else 0
        special_pct = (special_count / total_chars) * 100 if total_chars > 0 else 0

        # Calculate entropy (bits of randomness)
        charset_size = 0
        if uppercase_count > 0:
            charset_size += 26
        if lowercase_count > 0:
            charset_size += 26
        if number_count > 0:
            charset_size += 10
        if special_count > 0:
            charset_size += 33  # Approximate number of special characters

        # Entropy calculation: log2(charset_size^length)
        if charset_size > 0:
            import math
            entropy = length * math.log2(charset_size)
            entropy_str = f"{entropy:.1f} bits"
        else:
            entropy_str = "N/A"

        # Strength assessment
        if entropy < 45:
            strength = "Weak"
            style = "danger.TLabel"
        elif entropy < 60:
            strength = "Moderate"
            style = "info.TLabel"
        elif entropy < 80:
            strength = "Strong"
            style = "success.TLabel"
        else:
            strength = "Very Strong"
            style = "primary.TLabel"

        # Format the statistics string
        stats = f"Generated 1 password with length {length} chars\n"
        stats += f"Character distribution: "
        stats += f"Uppercase {uppercase_pct:.1f}%, "
        stats += f"Lowercase {lowercase_pct:.1f}%, "
        stats += f"Numbers {number_pct:.1f}%, "
        stats += f"Special {special_pct:.1f}%\n"
        stats += f"Entropy: {entropy_str}"

        # Update the labels
        self.stats_text.config(text=stats)
        self.strength_text.config(text="Strength:")
        self.strength_label.config(text=strength, style=style)

    def save_single_password_to_file(self):
        """Save the current single password to a file"""
        password = self.password_display.get(1.0, tb.END).strip()
        if not password:
            messagebox.showerror("Error", "No password generated to save")
            return

        # Ask for file location if not already specified
        if not self.single_output_file_var.get():
            file_path = filedialog.asksaveasfilename(
                title="Save Password To File",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if not file_path:
                return  # User cancelled
            self.single_output_file_var.set(file_path)

        try:
            with open(self.single_output_file_var.get(), 'w') as f:
                f.write(password)
            messagebox.showinfo("Success", "Password saved to file successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save password: {str(e)}")

    def _update_progress_ui(self, progress_info):
        """Update UI with progress information (safe to call from main thread)"""
        try:
            # Force a direct console update for progress info every time
            if 'passwords_written' in progress_info and 'elapsed' in progress_info:
                elapsed = progress_info['elapsed']
                # Direct console output - bypass any redirection
                sys.__stdout__.write(f"\rProgress: {progress_info['passwords_written']:,} passwords, "
                                    f"Time: {int(elapsed//60)}:{int(elapsed%60):02d}")
                if 'current_file_size' in progress_info:
                    size = progress_info['current_file_size']
                    if size < 1024**2:
                        size_str = f"{size/1024:.1f} KB"
                    elif size < 1024**3:
                        size_str = f"{size/(1024**2):.1f} MB"
                    else:
                        size_str = f"{size/(1024**3):.1f} GB"
                    sys.__stdout__.write(f", Size: {size_str}")
                sys.__stdout__.flush()

            # Update progress bar (ensure it's a value between 0-100)
            if 'percent_done' in progress_info:
                # Make sure we clamp the value to 0-100
                percent = min(max(progress_info['percent_done'], 0), 100)
                self.progress_var.set(percent)
                # Force UI update for progress bar
                self.update_idletasks()
                # Ensure the progress bar is visible and redrawn
                self.progress_bar.update()

            # Update status display
            elapsed = progress_info['elapsed']
            hours = int(elapsed // 3600)
            minutes = int((elapsed % 3600) // 60)
            seconds = int(elapsed % 60)

            # Basic status information
            status = (
                f"Progress: {progress_info['passwords_written']:,} / "
                f"{progress_info['total_passwords']:,} "
                f"({progress_info['percent_done']:.2f}%)\n"
            )

            # Add actual generation rate if available (from our measurements)
            if 'actual_rate' in progress_info:
                status += f"Speed: {progress_info['actual_rate']:.2f} passwords/sec\n"
            else:
                status += f"Speed: {progress_info['passwords_per_sec']:.2f} passwords/sec\n"

            # Add elapsed time
            status += f"Elapsed time: {hours:02}:{minutes:02}:{seconds:02}\n"

            # Add estimated time remaining if available
            if 'time_remaining' in progress_info:
                status += f"Estimated time remaining: {progress_info['time_remaining']}\n"

            # Add file size information if we have enough data
            if 'passwords_written' in progress_info and progress_info['passwords_written'] > 0:
                # Estimate file size based on passwords written
                length = self.length_var.get()
                bytes_per_password = length + 1  # Password + newline
                bytes_written = progress_info['passwords_written'] * bytes_per_password

                # Format for display
                if bytes_written < 1024:
                    size_str = f"{bytes_written} bytes"
                elif bytes_written < 1024**2:
                    size_str = f"{bytes_written/1024:.2f} KB"
                elif bytes_written < 1024**3:
                    size_str = f"{bytes_written/(1024**2):.2f} MB"
                else:
                    size_str = f"{bytes_written/(1024**3):.2f} GB"

                status += f"File size: {size_str}\n"

            self.status_display.delete(1.0, tb.END)
            self.status_display.insert(tb.END, status)
        except Exception as e:
            print(f"Error updating progress UI: {e}")

    def generate_multiple_passwords(self):
        """Generate multiple passwords and display them"""
        try:
            # Get password parameters
            count = self.password_count_var.get()
            length = self.length_var.get()
            use_uppercase = self.use_uppercase_var.get()
            use_lowercase = self.use_lowercase_var.get()
            use_numbers = self.use_numbers_var.get()
            use_special = self.use_special_var.get()

            # Validate at least one character type is selected
            if not (use_uppercase or use_lowercase or use_numbers or use_special):
                messagebox.showerror("Error", "At least one character type must be selected")
                return

            # Generate passwords with fixed length
            passwords = generate_passwords_in_parallel(
                count=count,
                length=length,
                use_uppercase=use_uppercase,
                use_lowercase=use_lowercase,
                use_numbers=use_numbers,
                use_special=use_special
            )

            # Display the passwords
            self.batch_display.delete(1.0, tb.END)
            for i, password in enumerate(passwords, 1):
                self.batch_display.insert(tb.END, f"{i}. {password}\n")

            # Update statistics
            self.update_batch_stats(passwords)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate passwords: {str(e)}")

    def update_batch_stats(self, passwords):
        """Calculate and display statistics about the batch of passwords"""
        if not passwords:
            return

        # Calculate statistics
        total_passwords = len(passwords)
        avg_length = sum(len(p) for p in passwords) / total_passwords

        # Counting character types
        uppercase_chars = sum(sum(1 for c in p if c in string.ascii_uppercase) for p in passwords)
        lowercase_chars = sum(sum(1 for c in p if c in string.ascii_lowercase) for p in passwords)
        number_chars = sum(sum(1 for c in p if c in string.digits) for p in passwords)
        special_chars = sum(sum(1 for c in p if c in string.punctuation) for p in passwords)

        total_chars = sum(len(p) for p in passwords)

        # Calculate percentages
        uppercase_pct = (uppercase_chars / total_chars) * 100 if total_chars > 0 else 0
        lowercase_pct = (lowercase_chars / total_chars) * 100 if total_chars > 0 else 0
        number_pct = (number_chars / total_chars) * 100 if total_chars > 0 else 0
        special_pct = (special_chars / total_chars) * 100 if total_chars > 0 else 0

        # Calculate average entropy
        charset_size = 0
        if uppercase_chars > 0:
            charset_size += 26
        if lowercase_chars > 0:
            charset_size += 26
        if number_chars > 0:
            charset_size += 10
        if special_chars > 0:
            charset_size += 33

        if charset_size > 0:
            import math
            entropy = avg_length * math.log2(charset_size)
            entropy_str = f"{entropy:.1f} bits"
        else:
            entropy_str = "N/A"

        # Strength assessment
        if entropy < 45:
            strength = "Weak"
            style = "danger.TLabel"
        elif entropy < 60:
            strength = "Moderate"
            style = "info.TLabel"
        elif entropy < 80:
            strength = "Strong"
            style = "success.TLabel"
        else:
            strength = "Very Strong"
            style = "primary.TLabel"

        # Format the statistics string
        stats = f"Generated {total_passwords} passwords with avg length {avg_length:.1f} chars\n"
        stats += f"Character distribution: "
        stats += f"Uppercase {uppercase_pct:.1f}%, "
        stats += f"Lowercase {lowercase_pct:.1f}%, "
        stats += f"Numbers {number_pct:.1f}%, "
        stats += f"Special {special_pct:.1f}%\n"
        stats += f"Entropy: {entropy_str}"

        # Update the labels
        self.batch_stats_label.config(text=stats)
        self.batch_strength_text.config(text="Strength:")
        self.batch_strength_label.config(text=strength, style=style)

    def browse_batch_output_file(self):
        """Open a file dialog to select the batch output file"""
        file_path = filedialog.asksaveasfilename(
            title="Save Passwords To File",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            self.batch_output_file_var.set(file_path)

    def browse_output_file(self):
        """Open file dialog to select output file"""
        file_path = filedialog.asksaveasfilename(
            title="Save Passwords To File",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            self.output_file_var.set(file_path)

    def save_passwords_to_file(self):
        """Save the batch generated passwords to a file"""
        passwords = self.batch_display.get(1.0, tb.END).strip()
        if not passwords:
            messagebox.showerror("Error", "No passwords generated to save")
            return

        # Ask for file location if not already specified
        if not self.batch_output_file_var.get():
            file_path = filedialog.asksaveasfilename(
                title="Save Passwords To File",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if not file_path:
                return  # User cancelled
            self.batch_output_file_var.set(file_path)

        try:
            with open(self.batch_output_file_var.get(), 'w') as f:
                f.write(passwords)
            messagebox.showinfo("Success", "Passwords saved to file successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save passwords: {str(e)}")

    def copy_to_clipboard(self, text_widget):
        """Copy the currently displayed password(s) to clipboard"""
        password = text_widget.get(1.0, tb.END).strip()
        if password:
            self.clipboard_clear()
            self.clipboard_append(password)
            messagebox.showinfo("Success", "Password(s) copied to clipboard")
        else:
            messagebox.showerror("Error", "No password(s) to copy")

    def toggle_theme(self, event=None):
        """Toggle between light and dark themes"""
        if self.theme_mode.get() == "light":
            self.theme_mode.set("dark")
            self.theme_manager.apply_theme("dark")
            self.theme_button.configure(text="Light")
        else:
            self.theme_mode.set("light")
            self.theme_manager.apply_theme("light")
            self.theme_button.configure(text="Dark")

    def apply_theme(self):
        """Apply the selected theme"""
        if self.theme_mode.get() == "dark":
            colors = self.theme_manager.apply_theme("dark")
            self.theme_button.configure(text="Light")
        else:
            colors = self.theme_manager.apply_theme("light")
            self.theme_button.configure(text="Dark")

    def update_active_tab_stats(self):
        """Update statistics based on the active tab"""
        current_tab = self.notebook.index(self.notebook.select())

        # Tab 0: Single password generator - update password stats if there's a password
        if current_tab == 0:
            password = self.password_display.get(1.0, tb.END).strip()
            if password:
                self.update_password_stats(password)

        # Tab 1: Batch generator - update batch stats if there are passwords
        elif current_tab == 1:
            passwords_text = self.batch_display.get(1.0, tb.END).strip()
            if passwords_text:
                # Split into individual passwords (assuming format "1. password\n2. password\n...")
                passwords = [line.split(". ", 1)[1] for line in passwords_text.split("\n") if ". " in line]
                if passwords:
                    self.update_batch_stats(passwords)

    def _on_closing(self):
        """Clean up and close the application"""
        # Cancel any scheduled after callbacks
        for after_id in self.after_ids:
            try:
                self.after_cancel(after_id)
            except:
                pass
                
        # Stop any running generation thread
        self.stop_generation = True
        
        # Wait a moment for threads to clean up
        if self.generation_thread and self.generation_thread.is_alive():
            self.generation_thread.join(0.5)  # Wait up to 0.5 seconds
        
        # Clean up password manager if it exists
        if hasattr(self, 'manager_tab') and self.manager_tab and hasattr(self.manager_tab, 'password_db'):
            if self.manager_tab.is_open and self.manager_tab.password_db:
                self.manager_tab.password_db.close_database()
            
        # Destroy the window
        self.destroy()


# Run the application if this script is executed directly
if __name__ == "__main__":
    app = PasswordGeneratorApp()
    app.center_window()
    app.mainloop()
