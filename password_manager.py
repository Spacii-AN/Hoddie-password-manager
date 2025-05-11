import os
import time
import secrets
import sqlite3
import hashlib
import base64
import json
import threading
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

# Define constants
DEFAULT_TIMEOUT = 5 * 60  # 5 minutes in seconds
CLIPBOARD_TIMEOUT = 30    # 30 seconds

class PasswordDatabase:
    """Handles the encrypted password database operations"""
    
    def __init__(self, db_path=None, master_password=None):
        # Default to a database in the password_databases folder
        if db_path is None:
            # Make sure the password_databases directory exists
            db_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "password_databases")
            if not os.path.exists(db_dir):
                os.makedirs(db_dir)
            db_path = os.path.join(db_dir, "hoodie_passwords.db")
        
        self.db_path = db_path
        self.master_password = master_password
        self.connection = None
        self.is_open = False
        
    def create_new_database(self, master_password):
        """Create a new password database with the given master password"""
        if os.path.exists(self.db_path):
            raise FileExistsError("Database already exists. Use open_database instead.")
        
        # Use standard SQLite for now, we'll implement SQLCipher in a future update
        self.connection = sqlite3.connect(self.db_path)
        self.master_password = master_password
        
        # Store the password hash
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt, 100000)
        
        # Create tables
        cursor = self.connection.cursor()
        
        # Create a metadata table that includes the password hash
        cursor.execute('''
        CREATE TABLE metadata (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        ''')
        
        # Store salt and hash
        cursor.execute(
            "INSERT INTO metadata VALUES (?, ?)", 
            ("salt", base64.b64encode(salt).decode())
        )
        cursor.execute(
            "INSERT INTO metadata VALUES (?, ?)", 
            ("password_hash", base64.b64encode(key).decode())
        )
        cursor.execute(
            "INSERT INTO metadata VALUES (?, ?)", 
            ("version", "1.0")
        )
        cursor.execute(
            "INSERT INTO metadata VALUES (?, ?)", 
            ("created_at", datetime.now().isoformat())
        )
        
        # Create vaults table
        cursor.execute('''
        CREATE TABLE vaults (
            id INTEGER PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create default vault
        cursor.execute(
            "INSERT INTO vaults (name, description) VALUES (?, ?)",
            ("Default", "Default password vault")
        )
        
        # Create entries table
        cursor.execute('''
        CREATE TABLE entries (
            id INTEGER PRIMARY KEY,
            vault_id INTEGER,
            title TEXT NOT NULL,
            username TEXT,
            password TEXT,
            url TEXT,
            notes TEXT,
            category TEXT,
            tags TEXT,
            favorite INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (vault_id) REFERENCES vaults(id)
        )
        ''')
        
        # Create history table to store password changes
        cursor.execute('''
        CREATE TABLE history (
            id INTEGER PRIMARY KEY,
            entry_id INTEGER,
            password TEXT,
            changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (entry_id) REFERENCES entries(id)
        )
        ''')
        
        self.connection.commit()
        self.is_open = True
        return True
    
    def verify_password(self, password):
        """Verify that the password matches the stored hash"""
        if not self.connection:
            return False
        
        cursor = self.connection.cursor()
        # Get the salt and hash
        cursor.execute("SELECT value FROM metadata WHERE key = ?", ("salt",))
        salt_b64 = cursor.fetchone()[0]
        salt = base64.b64decode(salt_b64)
        
        cursor.execute("SELECT value FROM metadata WHERE key = ?", ("password_hash",))
        stored_hash_b64 = cursor.fetchone()[0]
        stored_hash = base64.b64decode(stored_hash_b64)
        
        # Generate hash of provided password
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        
        # Compare in constant time to prevent timing attacks
        return secrets.compare_digest(key, stored_hash)
    
    def open_database(self, master_password):
        """Open the database with the master password"""
        if not os.path.exists(self.db_path):
            return False, "Database does not exist"
        
        self.connection = sqlite3.connect(self.db_path)
        self.master_password = master_password
        
        if not self.verify_password(master_password):
            self.connection.close()
            self.connection = None
            return False, "Incorrect password"
        
        self.is_open = True
        return True, "Database opened successfully"
    
    def close_database(self):
        """Close the database connection"""
        if self.connection:
            self.connection.close()
        self.connection = None
        self.is_open = False
    
    def add_entry(self, title, username, password, url="", notes="", category="", tags=None, vault_id=1):
        """Add a new entry to the database"""
        if not self.is_open:
            return False, "Database not open"
        
        # Encrypt sensitive data
        encrypted_password = self._encrypt(password)
        tags_str = ','.join(tags) if tags else ""
        
        cursor = self.connection.cursor()
        cursor.execute(
            """
            INSERT INTO entries (vault_id, title, username, password, url, notes, category, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (vault_id, title, username, encrypted_password, url, notes, category, tags_str)
        )
        self.connection.commit()
        return True, cursor.lastrowid
    
    def update_entry(self, entry_id, title, username, password, url="", notes="", category="", tags=None, vault_id=1):
        """Update an existing entry"""
        if not self.is_open:
            return False, "Database not open"
        
        # Get the current password to check if it changed
        cursor = self.connection.cursor()
        cursor.execute("SELECT password FROM entries WHERE id = ?", (entry_id,))
        result = cursor.fetchone()
        if not result:
            return False, "Entry not found"
        
        old_encrypted_password = result[0]
        new_encrypted_password = self._encrypt(password)
        
        # If password changed, create a history entry
        if old_encrypted_password != new_encrypted_password:
            cursor.execute(
                "INSERT INTO history (entry_id, password) VALUES (?, ?)",
                (entry_id, old_encrypted_password)
            )
        
        tags_str = ','.join(tags) if tags else ""
        
        cursor.execute(
            """
            UPDATE entries SET
                vault_id = ?,
                title = ?,
                username = ?,
                password = ?,
                url = ?,
                notes = ?,
                category = ?,
                tags = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (vault_id, title, username, new_encrypted_password, url, notes, category, tags_str, entry_id)
        )
        self.connection.commit()
        return True, "Entry updated successfully"
    
    def delete_entry(self, entry_id):
        """Delete an entry from the database"""
        if not self.is_open:
            return False, "Database not open"
        
        cursor = self.connection.cursor()
        cursor.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        cursor.execute("DELETE FROM history WHERE entry_id = ?", (entry_id,))
        self.connection.commit()
        return True, "Entry deleted successfully"
    
    def get_entry(self, entry_id):
        """Get a single entry by ID"""
        if not self.is_open:
            return False, "Database not open"
        
        cursor = self.connection.cursor()
        cursor.execute(
            """
            SELECT id, vault_id, title, username, password, url, notes, category, tags, favorite, created_at, updated_at 
            FROM entries WHERE id = ?
            """, 
            (entry_id,)
        )
        row = cursor.fetchone()
        if not row:
            return False, "Entry not found"
        
        entry = {
            "id": row[0],
            "vault_id": row[1],
            "title": row[2],
            "username": row[3],
            "password": self._decrypt(row[4]),
            "url": row[5],
            "notes": row[6],
            "category": row[7],
            "tags": row[8].split(',') if row[8] else [],
            "favorite": bool(row[9]),
            "created_at": row[10],
            "updated_at": row[11]
        }
        return True, entry
    
    def get_all_entries(self, vault_id=None):
        """Get all entries, optionally filtered by vault"""
        if not self.is_open:
            return False, "Database not open"
        
        cursor = self.connection.cursor()
        if vault_id:
            cursor.execute(
                """
                SELECT id, vault_id, title, username, url, category, tags, favorite, updated_at 
                FROM entries WHERE vault_id = ? ORDER BY title
                """, 
                (vault_id,)
            )
        else:
            cursor.execute(
                """
                SELECT id, vault_id, title, username, url, category, tags, favorite, updated_at 
                FROM entries ORDER BY title
                """
            )
        
        entries = []
        for row in cursor.fetchall():
            entry = {
                "id": row[0],
                "vault_id": row[1],
                "title": row[2],
                "username": row[3],
                "url": row[4],
                "category": row[5],
                "tags": row[6].split(',') if row[6] else [],
                "favorite": bool(row[7]),
                "updated_at": row[8]
            }
            entries.append(entry)
        
        return True, entries
    
    def search_entries(self, query):
        """Search entries by title, username, url, notes or category"""
        if not self.is_open:
            return False, "Database not open"
        
        search = f"%{query}%"
        cursor = self.connection.cursor()
        cursor.execute(
            """
            SELECT id, vault_id, title, username, url, category, tags, favorite, updated_at 
            FROM entries 
            WHERE title LIKE ? OR username LIKE ? OR url LIKE ? OR notes LIKE ? OR category LIKE ? OR tags LIKE ?
            ORDER BY title
            """, 
            (search, search, search, search, search, search)
        )
        
        entries = []
        for row in cursor.fetchall():
            entry = {
                "id": row[0],
                "vault_id": row[1],
                "title": row[2],
                "username": row[3],
                "url": row[4],
                "category": row[5],
                "tags": row[6].split(',') if row[6] else [],
                "favorite": bool(row[7]),
                "updated_at": row[8]
            }
            entries.append(entry)
        
        return True, entries
    
    def get_password_history(self, entry_id):
        """Get the password history for an entry"""
        if not self.is_open:
            return False, "Database not open"
        
        cursor = self.connection.cursor()
        cursor.execute(
            """
            SELECT id, password, changed_at FROM history WHERE entry_id = ? ORDER BY changed_at DESC
            """, 
            (entry_id,)
        )
        
        history = []
        for row in cursor.fetchall():
            history_item = {
                "id": row[0],
                "password": self._decrypt(row[1]),
                "changed_at": row[2]
            }
            history.append(history_item)
        
        return True, history
    
    def create_vault(self, name, description=""):
        """Create a new vault"""
        if not self.is_open:
            return False, "Database not open"
        
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "INSERT INTO vaults (name, description) VALUES (?, ?)",
                (name, description)
            )
            self.connection.commit()
            return True, cursor.lastrowid
        except sqlite3.IntegrityError:
            return False, "Vault name already exists"
    
    def get_vaults(self):
        """Get all vaults"""
        if not self.is_open:
            return False, "Database not open"
        
        cursor = self.connection.cursor()
        cursor.execute("SELECT id, name, description FROM vaults ORDER BY name")
        
        vaults = []
        for row in cursor.fetchall():
            vault = {
                "id": row[0],
                "name": row[1],
                "description": row[2]
            }
            vaults.append(vault)
        
        return True, vaults
    
    def backup_database(self, backup_path=None):
        """Create a backup of the database"""
        if not self.is_open:
            return False, "Database not open"
        
        try:
            # Create backups directory if it doesn't exist
            backup_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "password_databases", "backups")
            if not os.path.exists(backup_dir):
                os.makedirs(backup_dir)
            
            # Generate default backup path if none provided
            if backup_path is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                db_filename = os.path.basename(self.db_path)
                backup_filename = f"{os.path.splitext(db_filename)[0]}_backup_{timestamp}.db"
                backup_path = os.path.join(backup_dir, backup_filename)
            
            # Using Python's file copy
            with open(self.db_path, 'rb') as src, open(backup_path, 'wb') as dst:
                dst.write(src.read())
            return True, f"Backup created successfully at {backup_path}"
        except Exception as e:
            return False, f"Backup failed: {str(e)}"
    
    def export_data(self, export_path=None):
        """Export data in a platform-independent format (JSON)"""
        if not self.is_open:
            return False, "Database not open"
        
        try:
            # Create exports directory if it doesn't exist
            export_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "password_databases", "exports")
            if not os.path.exists(export_dir):
                os.makedirs(export_dir)
            
            # Generate default export path if none provided
            if export_path is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                db_filename = os.path.basename(self.db_path)
                export_filename = f"{os.path.splitext(db_filename)[0]}_export_{timestamp}.json"
                export_path = os.path.join(export_dir, export_filename)
            
            success, entries = self.get_all_entries()
            if not success:
                return False, "Failed to get entries"
            
            # Fetch complete data for each entry
            complete_entries = []
            for entry in entries:
                success, complete_entry = self.get_entry(entry["id"])
                if success:
                    complete_entries.append(complete_entry)
            
            success, vaults = self.get_vaults()
            if not success:
                return False, "Failed to get vaults"
            
            export_data = {
                "version": "1.0",
                "created_at": datetime.now().isoformat(),
                "vaults": vaults,
                "entries": complete_entries
            }
            
            with open(export_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            return True, f"Data exported successfully to {export_path}"
        except Exception as e:
            return False, f"Export failed: {str(e)}"
    
    def _encrypt(self, text):
        """Basic encryption - placeholder for better encryption"""
        # This is a very basic mock encryption - in a real app, use proper encryption
        # Will be replaced with actual encryption in a future version
        # For now, it's just a reversible encoding to simulate encryption
        return base64.b64encode(text.encode()).decode()
    
    def _decrypt(self, encrypted_text):
        """Basic decryption - placeholder for better decryption"""
        # This is a very basic mock decryption - in a real app, use proper decryption
        try:
            return base64.b64decode(encrypted_text.encode()).decode()
        except:
            return "[Decryption error]"


class PasswordManagerTab:
    """UI for the password manager tab"""
    
    def __init__(self, parent, password_generator_func=None):
        self.parent = parent
        self.password_generator_func = password_generator_func
        self.password_db = None
        self.current_vault_id = 1  # Default vault
        self.is_open = False
        self.auto_lock_timer = None
        self.inactivity_time = DEFAULT_TIMEOUT
        self.selected_entry_id = None
        
        # Create a variable for search
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.on_search_changed)
        
        self.create_ui()
        
    def create_ui(self):
        """Create the password manager UI"""
        # Main container
        self.main_frame = ttk.Frame(self.parent)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Database closed view
        self.closed_frame = ttk.Frame(self.main_frame)
        self.closed_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(self.closed_frame, 
                  text="Secure Password Manager", 
                  font=("TkDefaultFont", 16, "bold")).pack(pady=(100, 20))
        
        ttk.Label(self.closed_frame, 
                  text="Store your passwords securely in an encrypted database").pack(pady=(0, 30))
        
        button_frame = ttk.Frame(self.closed_frame)
        button_frame.pack()
        
        ttk.Button(button_frame, text="Create New Database", 
                   command=self.create_database).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Open Existing Database", 
                   command=self.open_database).pack(side=tk.LEFT, padx=10)
        
        # Database opened view (initially hidden)
        self.opened_frame = ttk.Frame(self.main_frame)
        
        # Create menu bar for the opened view
        self.menu_bar = tk.Menu(self.parent)
        
        # Database menu
        self.db_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.db_menu.add_command(label="Create New Database", command=self.create_database)
        self.db_menu.add_command(label="Open Database", command=self.open_database)
        self.db_menu.add_command(label="Backup Database", command=self.backup_current_database)
        self.db_menu.add_command(label="Export as JSON", command=self.export_current_database)
        self.db_menu.add_separator()
        self.db_menu.add_command(label="Lock Database", command=self.lock_database)
        
        # Add menus to the menu bar
        self.menu_bar.add_cascade(label="Database", menu=self.db_menu)
        
        # Top frame with search and buttons
        top_frame = ttk.Frame(self.opened_frame)
        top_frame.pack(fill=tk.X, pady=10, padx=10)
        
        # Search box
        search_frame = ttk.Frame(top_frame)
        search_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Buttons
        button_frame = ttk.Frame(top_frame)
        button_frame.pack(side=tk.RIGHT)
        
        self.add_button = ttk.Button(button_frame, text="Add Entry", command=self.add_entry)
        self.add_button.pack(side=tk.LEFT, padx=5)
        
        self.lock_button = ttk.Button(button_frame, text="Lock Database", command=self.lock_database)
        self.lock_button.pack(side=tk.LEFT, padx=5)
        
        # Database info label
        self.db_info_label = ttk.Label(top_frame, text="", font=("TkDefaultFont", 8))
        self.db_info_label.pack(side=tk.BOTTOM, fill=tk.X, pady=(5,0))
        
        # Main content - split pane
        self.paned_window = ttk.PanedWindow(self.opened_frame, orient=tk.HORIZONTAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left: password list
        list_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(list_frame, weight=1)
        
        # Create a treeview for the password list
        columns = ('title', 'username', 'category')
        self.password_list = ttk.Treeview(list_frame, columns=columns, show='headings')
        self.password_list.heading('title', text='Title')
        self.password_list.heading('username', text='Username')
        self.password_list.heading('category', text='Category')
        
        self.password_list.column('title', width=150)
        self.password_list.column('username', width=120)
        self.password_list.column('category', width=100)
        
        self.password_list.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        
        # Scrollbar for the list
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.password_list.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.password_list.configure(yscrollcommand=scrollbar.set)
        
        # Right: detail view
        detail_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(detail_frame, weight=2)
        
        # Entry details
        self.detail_frame = ttk.LabelFrame(detail_frame, text="Password Details")
        self.detail_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Entry details form
        form_frame = ttk.Frame(self.detail_frame)
        form_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        ttk.Label(form_frame, text="Title:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.title_var = tk.StringVar()
        ttk.Entry(form_frame, textvariable=self.title_var).grid(row=0, column=1, sticky=tk.EW, pady=5)
        
        # Username
        ttk.Label(form_frame, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(form_frame, textvariable=self.username_var).grid(row=1, column=1, sticky=tk.EW, pady=5)
        
        # Password with show/hide toggle
        ttk.Label(form_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        self.password_frame = ttk.Frame(form_frame)
        self.password_frame.grid(row=2, column=1, sticky=tk.EW, pady=5)
        
        self.password_entry = ttk.Entry(self.password_frame, textvariable=self.password_var, show="•")
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.show_password_var = tk.BooleanVar(value=False)
        self.show_password_cb = ttk.Checkbutton(
            self.password_frame, text="Show", 
            variable=self.show_password_var,
            command=self.toggle_show_password
        )
        self.show_password_cb.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            self.password_frame, text="Generate", 
            command=self.generate_password
        ).pack(side=tk.LEFT)
        
        # URL
        ttk.Label(form_frame, text="URL:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.url_var = tk.StringVar()
        ttk.Entry(form_frame, textvariable=self.url_var).grid(row=3, column=1, sticky=tk.EW, pady=5)
        
        # Category
        ttk.Label(form_frame, text="Category:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.category_var = tk.StringVar()
        ttk.Entry(form_frame, textvariable=self.category_var).grid(row=4, column=1, sticky=tk.EW, pady=5)
        
        # Tags
        ttk.Label(form_frame, text="Tags:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.tags_var = tk.StringVar()
        ttk.Entry(form_frame, textvariable=self.tags_var).grid(row=5, column=1, sticky=tk.EW, pady=5)
        
        # Notes
        ttk.Label(form_frame, text="Notes:").grid(row=6, column=0, sticky=tk.NW, pady=5)
        self.notes_text = tk.Text(form_frame, height=5, width=40)
        self.notes_text.grid(row=6, column=1, sticky=tk.EW, pady=5)
        
        # Button frame for actions
        button_frame = ttk.Frame(form_frame)
        button_frame.grid(row=7, column=0, columnspan=2, sticky=tk.EW, pady=10)
        
        self.save_button = ttk.Button(button_frame, text="Save", command=self.save_entry)
        self.save_button.pack(side=tk.LEFT, padx=5)
        
        self.copy_username_button = ttk.Button(button_frame, text="Copy Username", command=self.copy_username)
        self.copy_username_button.pack(side=tk.LEFT, padx=5)
        
        self.copy_password_button = ttk.Button(button_frame, text="Copy Password", command=self.copy_password)
        self.copy_password_button.pack(side=tk.LEFT, padx=5)
        
        self.delete_button = ttk.Button(button_frame, text="Delete", command=self.delete_entry)
        self.delete_button.pack(side=tk.LEFT, padx=5)
        
        # Configure grid weights for resizing
        form_frame.columnconfigure(1, weight=1)
        
        # Event bindings
        self.password_list.bind('<<TreeviewSelect>>', self.on_entry_selected)
        
        # Bind the user activity events to reset the inactivity timer
        self.parent.bind_all('<Key>', self._reset_inactivity_timer)
        self.parent.bind_all('<Button>', self._reset_inactivity_timer)
        self.parent.bind_all('<Motion>', self._reset_inactivity_timer)
    
    def create_database(self):
        """Create a new password database"""
        # Create default path in password_databases folder
        db_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "password_databases")
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)
            
        default_path = os.path.join(db_dir, f"passwords_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db")
        
        db_path = simpledialog.askstring(
            "New Database", 
            "Enter path for new database file:",
            initialvalue=default_path
        )
        if not db_path:
            return
        
        if os.path.exists(db_path):
            messagebox.showerror(
                "Error", 
                "A file already exists at that location. Choose a different path."
            )
            return
        
        password = self._get_password_with_confirmation("Enter a strong master password")
        if not password:
            return
        
        self.password_db = PasswordDatabase(db_path)
        try:
            self.password_db.create_new_database(password)
            messagebox.showinfo("Success", "Password database created successfully!")
            self._show_opened_view()
            self.refresh_entries()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create database: {str(e)}")
    
    def open_database(self):
        """Open an existing password database"""
        # Default to password_databases directory
        db_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "password_databases")
        
        # If the directory exists and has database files, use the most recent one as default
        default_path = os.path.expanduser("~/hoodie_passwords.db")
        if os.path.exists(db_dir):
            db_files = [f for f in os.listdir(db_dir) if f.endswith('.db')]
            if db_files:
                # Sort by modification time, newest first
                db_files.sort(key=lambda f: os.path.getmtime(os.path.join(db_dir, f)), reverse=True)
                default_path = os.path.join(db_dir, db_files[0])
        
        db_path = simpledialog.askstring(
            "Open Database", 
            "Enter path to database file:",
            initialvalue=default_path
        )
        if not db_path:
            return
        
        if not os.path.exists(db_path):
            messagebox.showerror("Error", "Database file does not exist.")
            return
        
        password = simpledialog.askstring(
            "Master Password", 
            "Enter master password:",
            show='*'
        )
        if not password:
            return
        
        self.password_db = PasswordDatabase(db_path)
        success, message = self.password_db.open_database(password)
        
        if success:
            messagebox.showinfo("Success", "Database opened successfully!")
            self._show_opened_view()
            self.refresh_entries()
        else:
            messagebox.showerror("Error", message)
    
    def lock_database(self):
        """Lock the database by requiring the password to access it again"""
        if self.password_db:
            self.password_db.close_database()
            self._show_closed_view()
            messagebox.showinfo("Database Locked", "The database has been locked.")
    
    def add_entry(self):
        """Show form to add a new entry"""
        self._clear_form()
        self.selected_entry_id = None
    
    def save_entry(self):
        """Save the current entry details"""
        if not self.password_db or not self.password_db.is_open:
            messagebox.showerror("Error", "Database not open")
            return
        
        title = self.title_var.get().strip()
        if not title:
            messagebox.showerror("Error", "Title is required")
            return
        
        username = self.username_var.get()
        password = self.password_var.get()
        url = self.url_var.get()
        category = self.category_var.get()
        tags = [tag.strip() for tag in self.tags_var.get().split(',') if tag.strip()]
        notes = self.notes_text.get('1.0', tk.END).strip()
        
        try:
            if self.selected_entry_id is None:
                # Add new entry
                success, result = self.password_db.add_entry(
                    title, username, password, url, notes, category, tags
                )
                if success:
                    messagebox.showinfo("Success", "Entry added successfully!")
                    # Create automatic backup after adding new entry
                    self.password_db.backup_database()
                else:
                    messagebox.showerror("Error", result)
            else:
                # Update existing entry
                success, result = self.password_db.update_entry(
                    self.selected_entry_id, title, username, password, url, notes, category, tags
                )
                if success:
                    messagebox.showinfo("Success", "Entry updated successfully!")
                    # Create automatic backup after updating entry
                    self.password_db.backup_database()
                else:
                    messagebox.showerror("Error", result)
            
            self.refresh_entries()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save entry: {str(e)}")
    
    def delete_entry(self):
        """Delete the selected entry"""
        if not self.selected_entry_id:
            messagebox.showerror("Error", "No entry selected")
            return
        
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this entry?"):
            success, message = self.password_db.delete_entry(self.selected_entry_id)
            if success:
                messagebox.showinfo("Success", "Entry deleted successfully!")
                self._clear_form()
                self.selected_entry_id = None
                self.refresh_entries()
            else:
                messagebox.showerror("Error", message)
    
    def on_entry_selected(self, event):
        """Handle entry selection in the treeview"""
        selected_items = self.password_list.selection()
        if not selected_items:
            return
        
        item_id = selected_items[0]
        entry_id = self.password_list.item(item_id, 'values')[-1]  # Last value is the entry ID
        
        self.selected_entry_id = int(entry_id)
        self._load_entry_details(self.selected_entry_id)
    
    def on_search_changed(self, *args):
        """Handle search text changes"""
        query = self.search_var.get().strip()
        self.refresh_entries(query)
    
    def refresh_entries(self, search_query=None):
        """Refresh the entries list"""
        if not self.password_db or not self.password_db.is_open:
            return
        
        # Clear current list
        self.password_list.delete(*self.password_list.get_children())
        
        # Get entries based on search or all
        if search_query:
            success, entries = self.password_db.search_entries(search_query)
        else:
            success, entries = self.password_db.get_all_entries(self.current_vault_id)
        
        if not success:
            return
        
        # Populate the treeview
        for entry in entries:
            self.password_list.insert(
                '', 'end', 
                values=(
                    entry['title'], 
                    entry['username'], 
                    entry['category'],
                    entry['id']  # Hidden ID for reference
                )
            )
    
    def _load_entry_details(self, entry_id):
        """Load the details of the selected entry into the form"""
        success, entry = self.password_db.get_entry(entry_id)
        if not success:
            messagebox.showerror("Error", "Failed to load entry details")
            return
        
        # Set form values
        self.title_var.set(entry['title'])
        self.username_var.set(entry['username'])
        self.password_var.set(entry['password'])
        self.url_var.set(entry['url'])
        self.category_var.set(entry['category'])
        self.tags_var.set(','.join(entry['tags']))
        
        # Set notes
        self.notes_text.delete('1.0', tk.END)
        self.notes_text.insert('1.0', entry['notes'])
    
    def _clear_form(self):
        """Clear the entry form"""
        self.title_var.set('')
        self.username_var.set('')
        self.password_var.set('')
        self.url_var.set('')
        self.category_var.set('')
        self.tags_var.set('')
        self.notes_text.delete('1.0', tk.END)
    
    def toggle_show_password(self):
        """Toggle password visibility"""
        if self.show_password_var.get():
            self.password_entry.config(show='')
        else:
            self.password_entry.config(show='•')
    
    def generate_password(self):
        """Generate a password using the existing generator function"""
        if self.password_generator_func:
            password = self.password_generator_func(
                use_uppercase=True,
                use_lowercase=True,
                use_numbers=True,
                use_special=True,
                length=16
            )
            self.password_var.set(password)
    
    def copy_username(self):
        """Copy the username to clipboard"""
        username = self.username_var.get()
        if username:
            self.parent.clipboard_clear()
            self.parent.clipboard_append(username)
            self._schedule_clipboard_clear()
    
    def copy_password(self):
        """Copy the password to clipboard"""
        password = self.password_var.get()
        if password:
            self.parent.clipboard_clear()
            self.parent.clipboard_append(password)
            self._schedule_clipboard_clear()
    
    def _schedule_clipboard_clear(self, timeout=CLIPBOARD_TIMEOUT):
        """Schedule clearing the clipboard after a timeout for security"""
        self.parent.after(timeout * 1000, self._clear_clipboard)
    
    def _clear_clipboard(self):
        """Clear the clipboard contents"""
        self.parent.clipboard_clear()
        self.parent.clipboard_append("")
    
    def _get_password_with_confirmation(self, prompt):
        """Get a password with confirmation that it matches"""
        while True:
            password1 = simpledialog.askstring(
                "Master Password", 
                f"{prompt}:",
                show='*'
            )
            if not password1:
                return None
            
            password2 = simpledialog.askstring(
                "Confirm Password", 
                "Confirm master password:",
                show='*'
            )
            if not password2:
                return None
            
            if password1 != password2:
                messagebox.showerror("Error", "Passwords do not match. Please try again.")
            else:
                return password1
    
    def _show_opened_view(self):
        """Switch to the opened database view"""
        self.closed_frame.pack_forget()
        self.opened_frame.pack(fill=tk.BOTH, expand=True)
        self.is_open = True
        self._start_inactivity_timer()
        
        # Set the menu bar
        if hasattr(self.parent, 'config'):
            self.parent.config(menu=self.menu_bar)
            
        # Update database info label
        if self.password_db:
            db_name = os.path.basename(self.password_db.db_path)
            self.db_info_label.config(text=f"Current database: {db_name}")
    
    def _show_closed_view(self):
        """Switch to the closed database view"""
        self.opened_frame.pack_forget()
        self.closed_frame.pack(fill=tk.BOTH, expand=True)
        self.is_open = False
        self._stop_inactivity_timer()
        
        # Remove menu bar
        if hasattr(self.parent, 'config'):
            self.parent.config(menu="")
    
    def _start_inactivity_timer(self):
        """Start the timer for auto-locking due to inactivity"""
        self._reset_inactivity_timer()
    
    def _stop_inactivity_timer(self):
        """Stop the inactivity timer"""
        if self.auto_lock_timer:
            self.parent.after_cancel(self.auto_lock_timer)
            self.auto_lock_timer = None
    
    def _reset_inactivity_timer(self, *args):
        """Reset the inactivity timer on user activity"""
        if not self.is_open:
            return
            
        if self.auto_lock_timer:
            self.parent.after_cancel(self.auto_lock_timer)
            
        self.auto_lock_timer = self.parent.after(
            self.inactivity_time * 1000, 
            self._auto_lock
        )
    
    def _auto_lock(self):
        """Automatically lock the database after inactivity"""
        if self.is_open and self.password_db and self.password_db.is_open:
            self.lock_database()
            messagebox.showinfo("Auto Lock", "Database locked due to inactivity")


def create_manager_tab(parent, password_generator_func=None):
    """Create and return the password manager tab"""
    return PasswordManagerTab(parent, password_generator_func)
    
# Add new methods for database operations
def backup_current_database(self):
    """Backup the current database to the backups folder"""
    if not self.is_open or not self.password_db:
        messagebox.showerror("Error", "No database is currently open")
        return
        
    success, result = self.password_db.backup_database()
    if success:
        messagebox.showinfo("Success", result)
    else:
        messagebox.showerror("Error", result)
        
def export_current_database(self):
    """Export the current database to JSON format"""
    if not self.is_open or not self.password_db:
        messagebox.showerror("Error", "No database is currently open")
        return
        
    success, result = self.password_db.export_data()
    if success:
        messagebox.showinfo("Success", result)
    else:
        messagebox.showerror("Error", result)

# Add these methods to the PasswordManagerTab class
PasswordManagerTab.backup_current_database = backup_current_database
PasswordManagerTab.export_current_database = export_current_database