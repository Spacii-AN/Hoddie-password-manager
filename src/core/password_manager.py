import os
import base64
import sqlite3
import hashlib
import json
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Global user manager instance
_user_manager = None

def get_user_manager():
    """Get the singleton user manager instance"""
    global _user_manager
    if _user_manager is None:
        _user_manager = UserManager()
    return _user_manager

class UserManager:
    """Manages user authentication and session state"""
    def __init__(self):
        self.current_user = None
        self.password_databases = {}  # Map username -> SecurePasswordDatabase
        self.default_db_dir = os.path.join(os.path.expanduser("~"), ".hoodie_passwords")
        
        # Create the default directory if it doesn't exist
        if not os.path.exists(self.default_db_dir):
            os.makedirs(self.default_db_dir)

    def login(self, username, password, db_path=None):
        """Authenticate a user and return success status"""
        if not db_path:
            # Use default location: ~/.hoodie_passwords/username.db
            db_path = os.path.join(self.default_db_dir, f"{username}.db")
        
        # Create the database connection
        db = SecurePasswordDatabase(db_path, username, password)
        success, message = db.connect()
        
        if success:
            self.current_user = username
            self.password_databases[username] = db
            return True, message
        else:
            return False, message
    
    def logout(self):
        """Log out the current user"""
        if self.current_user and self.current_user in self.password_databases:
            self.password_databases[self.current_user].close_database()
            del self.password_databases[self.current_user]
        self.current_user = None
    
    def get_current_database(self):
        """Get the current user's password database"""
        if not self.current_user:
            return None
        return self.password_databases.get(self.current_user)
    
    def is_authenticated(self):
        """Check if a user is currently logged in"""
        return self.current_user is not None


class SecurePasswordDatabase:
    """Encrypted password storage with SQLite backend"""
    def __init__(self, db_path, username, master_password):
        self.db_path = db_path
        self.username = username
        self.master_password = master_password
        self.connection = None
        self.fernet = None
        self.is_open = False

    def connect(self):
        """Connect to the database and authenticate"""
        self.connection = sqlite3.connect(self.db_path)
        self._init_tables()
        success, message = self._verify_or_create_user()
        if success:
            self.is_open = True
        return success, message

    def _init_tables(self):
        """Initialize database tables if they don't exist"""
        cursor = self.connection.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS users ("
                       "username TEXT PRIMARY KEY,"
                       "salt BLOB NOT NULL,"
                       "key_hash TEXT NOT NULL,"
                       "created_at TEXT NOT NULL)")
        
        cursor.execute("CREATE TABLE IF NOT EXISTS passwords ("
                       "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                       "username TEXT NOT NULL,"
                       "site TEXT NOT NULL,"
                       "enc_data TEXT NOT NULL,"
                       "created_at TEXT NOT NULL,"
                       "updated_at TEXT,"
                       "category TEXT,"
                       "notes TEXT,"
                       "FOREIGN KEY (username) REFERENCES users(username))")
        
        # Create index for faster lookups
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_passwords_username ON passwords(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_passwords_site ON passwords(site)")
        
        self.connection.commit()

    def _derive_key(self, password, salt):
        """Derive encryption key from password and salt"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _verify_or_create_user(self):
        """Verify user credentials or create new user"""
        cursor = self.connection.cursor()
        cursor.execute("SELECT salt, key_hash FROM users WHERE username = ?", (self.username,))
        result = cursor.fetchone()
        
        if result:
            # Existing user - verify password
            salt, stored_key_hash = result
            key = self._derive_key(self.master_password, salt)
            self.fernet = Fernet(key)
            if hashlib.sha256(key).hexdigest() == stored_key_hash:
                return True, "User authenticated"
            else:
                return False, "Incorrect master password"
        else:
            # New user - create account
            salt = os.urandom(16)
            key = self._derive_key(self.master_password, salt)
            key_hash = hashlib.sha256(key).hexdigest()
            cursor.execute("INSERT INTO users (username, salt, key_hash, created_at) VALUES (?, ?, ?, ?)",
                           (self.username, salt, key_hash, datetime.now().isoformat()))
            self.connection.commit()
            self.fernet = Fernet(key)
            return True, "New user created"

    def add_entry(self, site, username, password, category=None, notes=None):
        """Add a new password entry"""
        encrypted = self.fernet.encrypt(json.dumps({
            "username": username,
            "password": password,
            "notes": notes or ""
        }).encode()).decode()
        
        now = datetime.now().isoformat()
        cursor = self.connection.cursor()
        cursor.execute("INSERT INTO passwords (username, site, enc_data, created_at, updated_at, category, notes) "
                       "VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (self.username, site, encrypted, now, now, category, None))
        self.connection.commit()
        return True

    def update_entry(self, entry_id, site=None, username=None, password=None, category=None, notes=None):
        """Update an existing password entry"""
        # First, get current entry
        cursor = self.connection.cursor()
        cursor.execute("SELECT enc_data FROM passwords WHERE id = ? AND username = ?", 
                      (entry_id, self.username))
        result = cursor.fetchone()
        
        if not result:
            return False, "Entry not found"
            
        try:
            # Decrypt existing data
            current_data = json.loads(self.fernet.decrypt(result[0].encode()).decode())
            
            # Update with new values if provided
            if username is not None:
                current_data["username"] = username
            if password is not None:
                current_data["password"] = password
            if notes is not None:
                current_data["notes"] = notes
                
            # Re-encrypt the updated data
            encrypted = self.fernet.encrypt(json.dumps(current_data).encode()).decode()
            
            # Update the database
            update_fields = []
            params = []
            
            if site is not None:
                update_fields.append("site = ?")
                params.append(site)
                
            if category is not None:
                update_fields.append("category = ?")
                params.append(category)
                
            # Always update the encrypted data and timestamp
            update_fields.append("enc_data = ?")
            update_fields.append("updated_at = ?")
            params.extend([encrypted, datetime.now().isoformat()])
            
            # Add the WHERE clause parameters
            params.extend([entry_id, self.username])
            
            # Construct and execute the query
            query = f"UPDATE passwords SET {', '.join(update_fields)} WHERE id = ? AND username = ?"
            cursor.execute(query, params)
            self.connection.commit()
            
            return True, "Entry updated"
            
        except (InvalidToken, json.JSONDecodeError) as e:
            return False, f"Decryption error: {str(e)}"

    def delete_entry(self, entry_id):
        """Delete a password entry"""
        cursor = self.connection.cursor()
        cursor.execute("DELETE FROM passwords WHERE id = ? AND username = ?", 
                      (entry_id, self.username))
        self.connection.commit()
        return cursor.rowcount > 0

    def get_entries(self, search_term=None, category=None):
        """Retrieve password entries with optional filtering"""
        cursor = self.connection.cursor()
        
        query = "SELECT id, site, enc_data, created_at, updated_at, category FROM passwords WHERE username = ?"
        params = [self.username]
        
        if search_term:
            query += " AND site LIKE ?"
            params.append(f"%{search_term}%")
            
        if category:
            query += " AND category = ?"
            params.append(category)
            
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        entries = []
        for id, site, enc_data, created_at, updated_at, category in rows:
            try:
                decrypted = self.fernet.decrypt(enc_data.encode()).decode()
                data = json.loads(decrypted)
                entries.append({
                    "id": id,
                    "site": site,
                    "username": data["username"],
                    "password": data["password"],
                    "notes": data.get("notes", ""),
                    "created_at": created_at,
                    "updated_at": updated_at or created_at,
                    "category": category or "Uncategorized"
                })
            except (InvalidToken, json.JSONDecodeError):
                # Skip entries that can't be decrypted
                continue
                
        return entries
        
    def get_categories(self):
        """Get list of all categories in use"""
        cursor = self.connection.cursor()
        cursor.execute("SELECT DISTINCT category FROM passwords WHERE username = ? AND category IS NOT NULL", 
                      (self.username,))
        categories = [row[0] for row in cursor.fetchall() if row[0]]
        categories.append("Uncategorized")  # Always include default category
        categories.sort()
        return categories
        
    def export_data(self, path, include_passwords=False):
        """Export database to JSON file"""
        entries = self.get_entries()
        export_data = {
            "exported_at": datetime.now().isoformat(),
            "username": self.username,
            "entries": []
        }
        
        for entry in entries:
            export_entry = {
                "site": entry["site"],
                "username": entry["username"],
                "category": entry["category"],
                "notes": entry["notes"],
                "created_at": entry["created_at"],
                "updated_at": entry["updated_at"]
            }
            
            if include_passwords:
                export_entry["password"] = entry["password"]
                
            export_data["entries"].append(export_entry)
            
        with open(path, 'w') as f:
            json.dump(export_data, f, indent=2)
            
        return True
        
    def import_data(self, path, password_generator=None):
        """Import entries from JSON file"""
        try:
            with open(path, 'r') as f:
                import_data = json.load(f)
                
            if "entries" not in import_data:
                return False, "Invalid file format"
                
            imported_count = 0
            entries = import_data["entries"]
            
            for entry in entries:
                site = entry.get("site")
                username = entry.get("username")
                category = entry.get("category", "Imported")
                notes = entry.get("notes", "")
                
                if not site or not username:
                    continue
                
                # Use imported password or generate a new one
                if "password" in entry:
                    password = entry["password"]
                elif password_generator:
                    password = password_generator(12, use_uppercase=True, use_lowercase=True, 
                                               use_numbers=True, use_special=True)
                else:
                    # Generate a simple password as fallback
                    password = "ChangeMe123!"
                
                self.add_entry(site, username, password, category, notes)
                imported_count += 1
                
            return True, f"Imported {imported_count} entries"
                
        except (json.JSONDecodeError, KeyError) as e:
            return False, f"Import error: {str(e)}"
            
    def close_database(self):
        """Close the database connection"""
        if self.connection:
            self.connection.close()
            self.connection = None
            self.is_open = False


def create_login_dialog(parent, callback=None):
    """Create a login dialog for user authentication"""
    dialog = tb.Toplevel(parent)
    dialog.title("Password Manager Login")
    dialog.geometry("400x350")
    dialog.resizable(False, False)
    
    # Make dialog modal
    dialog.transient(parent)
    dialog.grab_set()
    
    # Center the dialog
    dialog.update_idletasks()
    width = dialog.winfo_width()
    height = dialog.winfo_height()
    x = (dialog.winfo_screenwidth() // 2) - (width // 2)
    y = (dialog.winfo_screenheight() // 2) - (height // 2)
    dialog.geometry(f'{width}x{height}+{x}+{y}')
    
    # Create the form
    frame = tb.Frame(dialog, padding=20)
    frame.pack(fill=tb.BOTH, expand=True)
    
    # App title
    tb.Label(frame, text="Hoodie Password Manager", font=("Arial", 16, "bold")).pack(pady=(0, 20))
    
    # Username field
    username_frame = tb.Frame(frame)
    username_frame.pack(fill=tb.X, pady=5)
    tb.Label(username_frame, text="Username:", width=10).pack(side=tb.LEFT)
    username_var = tb.StringVar()
    username_entry = tb.Entry(username_frame, textvariable=username_var)
    username_entry.pack(side=tb.LEFT, fill=tb.X, expand=True)
    
    # Password field
    password_frame = tb.Frame(frame)
    password_frame.pack(fill=tb.X, pady=5)
    tb.Label(password_frame, text="Password:", width=10).pack(side=tb.LEFT)
    password_var = tb.StringVar()
    password_entry = tb.Entry(password_frame, textvariable=password_var, show="•")
    password_entry.pack(side=tb.LEFT, fill=tb.X, expand=True)
    
    # Database selection
    db_frame = tb.Frame(frame)
    db_frame.pack(fill=tb.X, pady=5)
    tb.Label(db_frame, text="Database:").pack(anchor=tb.W)
    
    db_path_var = tb.StringVar()
    db_path_entry = tb.Entry(db_frame, textvariable=db_path_var, state="readonly")
    db_path_entry.pack(fill=tb.X, expand=True, pady=5)
    
    db_select_frame = tb.Frame(db_frame)
    db_select_frame.pack(fill=tb.X)
    
    # Use local DB (default)
    def use_default_db():
        db_path_var.set("<Default location>")
        browse_button.config(state=tb.DISABLED)
    
    # Use custom DB file
    def use_custom_db():
        browse_button.config(state=tb.NORMAL)
        if not db_path_var.get() or db_path_var.get() == "<Default location>":
            db_path_var.set("")
    
    db_type_var = tb.StringVar(value="default")
    tb.Radiobutton(db_select_frame, text="Use default location", variable=db_type_var, 
                  value="default", command=use_default_db).pack(side=tb.LEFT)
    tb.Radiobutton(db_select_frame, text="Select file", variable=db_type_var, 
                  value="custom", command=use_custom_db).pack(side=tb.LEFT)
    
    # Browse button
    def browse_db_file():
        file_path = filedialog.askopenfilename(
            title="Select Password Database",
            filetypes=[("Database files", "*.db"), ("All files", "*.*")]
        )
        if file_path:
            db_path_var.set(file_path)
    
    browse_button = tb.Button(db_frame, text="Browse...", command=browse_db_file, state=tb.DISABLED)
    browse_button.pack(anchor=tb.E, pady=5)
    
    # Initialize default db path
    use_default_db()
    
    # Status message
    status_var = tb.StringVar()
    status_label = tb.Label(frame, textvariable=status_var, foreground="red")
    status_label.pack(pady=10)
    
    # Login function
    def do_login():
        username = username_var.get().strip()
        password = password_var.get()
        
        if not username:
            status_var.set("Please enter a username")
            return
            
        if not password:
            status_var.set("Please enter a password")
            return
            
        # Determine database path
        db_path = None
        if db_type_var.get() == "custom" and db_path_var.get() and db_path_var.get() != "<Default location>":
            db_path = db_path_var.get()
            
        # Show busy cursor
        dialog.config(cursor="wait")
        dialog.update()
        
        # Perform login
        user_manager = get_user_manager()
        success, message = user_manager.login(username, password, db_path)
        
        # Reset cursor
        dialog.config(cursor="")
        
        if success:
            if callback:
                callback(success)
            dialog.destroy()
        else:
            status_var.set(message)
    
    # Buttons
    button_frame = tb.Frame(frame)
    button_frame.pack(fill=tb.X, pady=10)
    
    tb.Button(button_frame, text="Login", style="primary", command=do_login).pack(side=tb.RIGHT, padx=5)
    tb.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tb.RIGHT, padx=5)
    
    # Focus the username field
    username_entry.focus_set()
    
    # Bind Enter key to login
    dialog.bind("<Return>", lambda event: do_login())
    
    return dialog


def create_manager_tab(parent, password_generator_func=None):
    """Create the password manager tab UI."""
    # Create main frame
    main_frame = tb.Frame(parent)
    main_frame.pack(fill=tb.BOTH, expand=True)
    
    # Create status bar
    status_frame = tb.Frame(main_frame)
    status_frame.pack(fill=tb.X, padx=5, pady=2)
    
    status_var = tb.StringVar(value="Not logged in")
    user_var = tb.StringVar()
    
    tb.Label(status_frame, textvariable=status_var).pack(side=tb.LEFT)
    tb.Label(status_frame, textvariable=user_var).pack(side=tb.RIGHT)
    
    # Create login/logout buttons
    button_frame = tb.Frame(main_frame)
    button_frame.pack(fill=tb.X, padx=5, pady=2)
    
    login_button = tb.Button(button_frame, text="Login")
    login_button.pack(side=tb.LEFT, padx=5)
    
    logout_button = tb.Button(button_frame, text="Logout", state=tb.DISABLED)
    logout_button.pack(side=tb.LEFT, padx=5)
    
    # Create content frame (initially hidden)
    content_frame = tb.Frame(main_frame)
    
    def import_passwords():
        """Import passwords from a file."""
        try:
            file_path = filedialog.askopenfilename(
                title="Import Passwords",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )
            if file_path:
    user_manager = get_user_manager()
                if user_manager.is_authenticated():
    db = user_manager.get_current_database()
                    db.import_data(file_path, password_generator_func)
                    messagebox.showinfo("Success", "Passwords imported successfully")
                    if 'load_passwords' in content_ui:
                        content_ui['load_passwords']()
    else:
                    messagebox.showerror("Error", "Please log in first")
        except Exception as e:
            logger.error(f"Error importing passwords: {e}")
            messagebox.showerror("Error", f"Failed to import passwords: {str(e)}")

def export_passwords():
        """Export passwords to a file."""
        try:
    file_path = filedialog.asksaveasfilename(
        title="Export Passwords",
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )
            if file_path:
    user_manager = get_user_manager()
                if user_manager.is_authenticated():
    db = user_manager.get_current_database()
                    db.export_data(file_path)
        messagebox.showinfo("Success", "Passwords exported successfully")
    else:
                    messagebox.showerror("Error", "Please log in first")
        except Exception as e:
            logger.error(f"Error exporting passwords: {e}")
            messagebox.showerror("Error", f"Failed to export passwords: {str(e)}")

    def create_content_ui():
        """Create the content UI elements."""
        # Toolbar frame
        toolbar = tb.Frame(content_frame)
        toolbar.pack(fill=tb.X, padx=5, pady=5)
        
        # Add button
        add_button = tb.Button(toolbar, text="Add Password")
        add_button.pack(side=tb.LEFT, padx=5)
        
        # Import/Export buttons
        import_button = tb.Button(toolbar, text="Import")
        import_button.pack(side=tb.LEFT, padx=5)
        
        export_button = tb.Button(toolbar, text="Export")
        export_button.pack(side=tb.LEFT, padx=5)
        
        # Search frame
        search_frame = tb.Frame(toolbar)
        search_frame.pack(side=tb.RIGHT, fill=tb.X, expand=True)
        
        search_entry = tb.Entry(search_frame)
        search_entry.pack(side=tb.LEFT, fill=tb.X, expand=True, padx=5)
        
        search_button = tb.Button(search_frame, text="Search")
        search_button.pack(side=tb.LEFT)
        
        # Category filter
        category_frame = tb.Frame(toolbar)
        category_frame.pack(side=tb.RIGHT, padx=5)
        
        tb.Label(category_frame, text="Category:").pack(side=tb.LEFT)
        category_var = tb.StringVar(value="All")
        category_menu = tb.OptionMenu(category_frame, category_var, "All")
        category_menu.pack(side=tb.LEFT, padx=5)
        
        # Password list
        list_frame = tb.Frame(content_frame)
        list_frame.pack(fill=tb.BOTH, expand=True, padx=5, pady=5)
        
        # Create treeview
        columns = ("Site", "Username", "Category", "Last Modified")
        tree = tb.Treeview(list_frame, columns=columns, show="headings")
        
        # Configure columns
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=100)
        
        # Add scrollbar
        scrollbar = tb.Scrollbar(list_frame, orient=tb.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack tree and scrollbar
        tree.pack(side=tb.LEFT, fill=tb.BOTH, expand=True)
        scrollbar.pack(side=tb.RIGHT, fill=tb.Y)
        
        # Context menu
        context_menu = tb.Menu(tree, tearoff=0)
        context_menu.add_command(label="View Details")
        context_menu.add_command(label="Edit")
        context_menu.add_command(label="Delete")
        context_menu.add_separator()
        context_menu.add_command(label="Copy Username")
        context_menu.add_command(label="Copy Password")
        
        def show_context_menu(event):
            item = tree.identify_row(event.y)
            if item:
                tree.selection_set(item)
                context_menu.post(event.x_root, event.y_root)
        
        tree.bind("<Button-3>", show_context_menu)

# Connect Import/Export buttons
import_button.config(command=import_passwords)
export_button.config(command=export_passwords)

# Double-click to view details
tree.bind("<Double-1>", lambda e: view_details())

return {
    "tree": tree,
    "load_passwords": load_passwords,
    "add_button": add_button,
    "import_button": import_button,
    "export_button": export_button,
    "search_entry": search_entry,
    "search_button": search_button,
    "category_menu": category_menu
}

# Create the content UI elements
content_ui = create_content_ui()

# Function to update UI state based on login status
def update_login_status():
    user_manager = get_user_manager()
    is_logged_in = user_manager.is_authenticated()
    
    if is_logged_in:
        current_user = user_manager.current_user
        status_var.set("Logged in")
        user_var.set(f"User: {current_user}")
        login_button.config(state=tb.DISABLED)
        logout_button.config(state=tb.NORMAL)
        
        # Show content frame
        content_frame.pack(fill=tb.BOTH, expand=True, padx=10, pady=10)
        
        # Load passwords
        content_ui["load_passwords"]()
    else:
        status_var.set("Not logged in")
        user_var.set("")
        login_button.config(state=tb.NORMAL)
        logout_button.config(state=tb.DISABLED)
        
        # Hide content frame
        content_frame.pack_forget()

# Login button function
def do_login():
    create_login_dialog(parent, callback=update_login_status)

# Logout button function
def do_logout():
    user_manager = get_user_manager()
    user_manager.logout()
    update_login_status()

# Connect buttons
login_button.config(command=do_login)
logout_button.config(command=do_logout)

# Initialize UI state
update_login_status()

return {
    "main_frame": main_frame,
    "login_button": login_button,
    "logout_button": logout_button,
    "update_login_status": update_login_status
}


# Function to create the main window
def create_main_window():
    # Create the main window
    root = tb.Window(themename="darkly")
    root.title("Hoodie Password Manager")
    root.geometry("800x600")
    
    # Create notebook (tab control)
    notebook = tb.Notebook(root)
    notebook.pack(fill=tb.BOTH, expand=True, padx=10, pady=10)
    
    # Define password generator function
    def generate_password(length=12, use_uppercase=True, use_lowercase=True, 
                         use_numbers=True, use_special=True):
        import random
        import string
        
        # Define character sets
        lowercase = string.ascii_lowercase if use_lowercase else ""
        uppercase = string.ascii_uppercase if use_uppercase else ""
        numbers = string.digits if use_numbers else ""
        special = "!@#$%^&*()-_=+[]{}|;:,.<>?/" if use_special else ""
        
        # Combine character sets
        charset = lowercase + uppercase + numbers + special
        
        if not charset:
            return ""
            
        # Ensure at least one character from each selected set is included
        password = []
        
        if use_lowercase:
            password.append(random.choice(string.ascii_lowercase))
        if use_uppercase:
            password.append(random.choice(string.ascii_uppercase))
        if use_numbers:
            password.append(random.choice(string.digits))
        if use_special:
            password.append(random.choice("!@#$%^&*()-_=+[]{}|;:,.<>?/"))
            
        # Fill remaining length with random characters
        remaining = length - len(password)
        password.extend(random.choices(charset, k=remaining))
        
        # Shuffle the password
        random.shuffle(password)
        
        return ''.join(password)
    
    # Create password manager tab
    manager_tab = tb.Frame(notebook)
    notebook.add(manager_tab, text="Password Manager")
    manager_ui = create_manager_tab(manager_tab, generate_password)
    
    # Create password generator tab
    generator_tab = tb.Frame(notebook)
    notebook.add(generator_tab, text="Password Generator")
    
    # Create Password Generator UI
    generator_frame = tb.Frame(generator_tab, padding=20)
    generator_frame.pack(fill=tb.BOTH, expand=True)
    
    tb.Label(generator_frame, text="Password Generator", font=("Arial", 16, "bold")).pack(pady=(0, 20))
    
    # Length slider
    length_frame = tb.Frame(generator_frame)
    length_frame.pack(fill=tb.X, pady=10)
    
    tb.Label(length_frame, text="Password Length:").pack(side=tb.LEFT)
    length_var = tb.IntVar(value=12)
    length_label = tb.Label(length_frame, textvariable=length_var, width=3)
    length_label.pack(side=tb.LEFT, padx=5)
    
    length_scale = tb.Scale(length_frame, from_=4, to=32, variable=length_var, 
                           orient=tb.HORIZONTAL)
    length_scale.pack(side=tb.LEFT, fill=tb.X, expand=True, padx=5)
    
    # Character set checkboxes
    charset_frame = tb.Frame(generator_frame)
    charset_frame.pack(fill=tb.X, pady=10)
    
    charset_label = tb.Label(charset_frame, text="Character Sets:")
    charset_label.grid(row=0, column=0, sticky=tb.W, pady=5)
    
    uppercase_var = tb.BooleanVar(value=True)
    lowercase_var = tb.BooleanVar(value=True)
    numbers_var = tb.BooleanVar(value=True)
    special_var = tb.BooleanVar(value=True)
    
    tb.Checkbutton(charset_frame, text="Uppercase (A-Z)", 
                  variable=uppercase_var).grid(row=1, column=0, sticky=tb.W)
    tb.Checkbutton(charset_frame, text="Lowercase (a-z)", 
                  variable=lowercase_var).grid(row=2, column=0, sticky=tb.W)
    tb.Checkbutton(charset_frame, text="Numbers (0-9)", 
                  variable=numbers_var).grid(row=1, column=1, sticky=tb.W)
    tb.Checkbutton(charset_frame, text="Special (!@#$%...)", 
                  variable=special_var).grid(row=2, column=1, sticky=tb.W)
    
    # Generated password
    password_frame = tb.Frame(generator_frame)
    password_frame.pack(fill=tb.X, pady=20)
    
    tb.Label(password_frame, text="Generated Password:").pack(anchor=tb.W)
    password_var = tb.StringVar()
    password_entry = tb.Entry(password_frame, textvariable=password_var, font=("Courier", 12))
    password_entry.pack(fill=tb.X, pady=5)
    
    # Generate button
    def do_generate():
        password = generate_password(
            length=length_var.get(),
            use_uppercase=uppercase_var.get(),
            use_lowercase=lowercase_var.get(),
            use_numbers=numbers_var.get(),
            use_special=special_var.get()
        )
        password_var.set(password)
    
    # Copy button
    def do_copy():
        if password_var.get():
            root.clipboard_clear()
            root.clipboard_append(password_var.get())
            messagebox.showinfo("Copied", "Password copied to clipboard")
    
    button_frame = tb.Frame(generator_frame)
    button_frame.pack(fill=tb.X, pady=10)
    
    tb.Button(button_frame, text="Generate", style="primary", 
             command=do_generate).pack(side=tb.LEFT, padx=5)
    tb.Button(button_frame, text="Copy to Clipboard", 
             command=do_copy).pack(side=tb.LEFT, padx=5)
    
    # Generate initial password
    do_generate()
    
    # Add Settings tab
    settings_tab = tb.Frame(notebook)
    notebook.add(settings_tab, text="Settings")
    
    settings_frame = tb.Frame(settings_tab, padding=20)
    settings_frame.pack(fill=tb.BOTH, expand=True)
    
    tb.Label(settings_frame, text="Settings", font=("Arial", 16, "bold")).pack(pady=(0, 20))
    
    # Theme selector
    theme_frame = tb.Frame(settings_frame)
    theme_frame.pack(fill=tb.X, pady=10)
    
    tb.Label(theme_frame, text="Theme:").pack(side=tb.LEFT)
    theme_var = tb.StringVar(value="darkly")
    
    themes = ["darkly", "cosmo", "flatly", "journal", "litera", "lumen", "solar", 
              "superhero", "united", "yeti", "pulse", "minty", "sandstone"]
    
    theme_menu = tb.OptionMenu(theme_frame, theme_var, *themes)
    theme_menu.pack(side=tb.LEFT, padx=10)
    
    # Theme change function
    def change_theme():
        new_theme = theme_var.get()
        style = tb.Style()
        style.theme_use(new_theme)
    
    tb.Button(theme_frame, text="Apply Theme", 
             command=change_theme).pack(side=tb.LEFT, padx=5)
    
    # Timeout settings
    timeout_frame = tb.Frame(settings_frame)
    timeout_frame.pack(fill=tb.X, pady=10)
    
    tb.Label(timeout_frame, text="Auto Logout:").pack(side=tb.LEFT)
    timeout_var = tb.IntVar(value=5)
    timeout_options = [("Never", 0), ("5 minutes", 5), ("10 minutes", 10), 
                      ("15 minutes", 15), ("30 minutes", 30), ("1 hour", 60)]
    
    timeout_menu = tb.OptionMenu(timeout_frame, timeout_var, *[v for _, v in timeout_options])
    timeout_menu.pack(side=tb.LEFT, padx=10)
    
    # Database settings
    db_frame = tb.Frame(settings_frame)
    db_frame.pack(fill=tb.X, pady=20)
    
    tb.Label(db_frame, text="Database", font=("Arial", 12, "bold")).pack(anchor=tb.W)
    
    # Backup button
    def backup_database():
        user_manager = get_user_manager()
        db = user_manager.get_current_database()
        
        if not db or not db.is_open:
            messagebox.showinfo("Not Connected", "Please login first")
            return
            
        # Ask for file location
        file_path = filedialog.asksaveasfilename(
            title="Backup Database",
            defaultextension=".db",
            filetypes=[("Database files", "*.db"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            # Simple file copy
            import shutil
            shutil.copy2(db.db_path, file_path)
            messagebox.showinfo("Success", "Database backup created successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Backup failed: {str(e)}")
    
    tb.Button(db_frame, text="Create Backup", 
             command=backup_database).pack(anchor=tb.W, pady=5)
    
    # About tab
    about_tab = tb.Frame(notebook)
    notebook.add(about_tab, text="About")
    
    about_frame = tb.Frame(about_tab, padding=20)
    about_frame.pack(fill=tb.BOTH, expand=True)
    
    tb.Label(about_frame, text="Hoodie Password Manager", 
            font=("Arial", 16, "bold")).pack(pady=(0, 10))
    tb.Label(about_frame, text="Version 1.0").pack()
    
    tb.Label(about_frame, text="A secure and convenient password manager", 
            font=("Arial", 10)).pack(pady=(20, 10))
    tb.Label(about_frame,   text="Developed by Your Name").pack()
    tb.Label(about_frame, text="2023").pack()
    tb.Label(about_frame, text="All rights reserved").pack() 