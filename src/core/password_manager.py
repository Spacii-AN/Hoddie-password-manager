import os
import base64
import hashlib
import json
import ctypes
import time
from datetime import datetime
from tkinter import messagebox, simpledialog, filedialog
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .user_manager import get_user_manager
import threading
import logging
from ..gui.account_import_export import create_account_import_export_tab
from ..utils.backup_manager import BackupManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security constants
SALT_SIZE = 32
SCRYPT_N = 2**14  # CPU/memory cost (increase for more security, decrease for more speed)
SCRYPT_R = 8      # Block size
SCRYPT_P = 4  # Parallelization: reduced for faster login/registration
SCRYPT_DKLEN = 32 # Output key length (256 bits)
NONCE_SIZE = 12
CLIPBOARD_TIMEOUT = 30  # seconds
SESSION_TIMEOUT = 300  # 5 minutes

def secure_memory_wipe(data):
    """Securely wipe sensitive data from memory"""
    if isinstance(data, (str, bytes)):
        if isinstance(data, str):
            data = data.encode('utf-8')
        # Overwrite the memory with random data
        ctypes.memset(ctypes.c_char_p(data), 0, len(data))
        # Overwrite again with ones
        ctypes.memset(ctypes.c_char_p(data), 1, len(data))
        # Final overwrite with zeros
        ctypes.memset(ctypes.c_char_p(data), 0, len(data))

def secure_clipboard_clear():
    """Clear the clipboard after timeout"""
    import tkinter as tk
    root = tk.Tk()
    root.withdraw()
    root.clipboard_clear()
    root.destroy()

def copy_to_clipboard(text):
    """Copy text to clipboard with automatic clearing"""
    import tkinter as tk
    root = tk.Tk()
    root.withdraw()
    root.clipboard_clear()
    root.clipboard_append(text)
    root.destroy()
    
    # Schedule clipboard clearing
    root.after(CLIPBOARD_TIMEOUT * 1000, secure_clipboard_clear)

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a key using scrypt (memory-hard, secure)"""
    try:
        key = hashlib.scrypt(
            password.encode() if isinstance(password, str) else password,
            salt=salt,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=SCRYPT_DKLEN
        )
        return key
    finally:
        secure_memory_wipe(password)

def encrypt_data(data: dict, key: bytes) -> bytes:
    """Encrypt data using AES-256-GCM with authentication"""
    try:
        # Generate a random nonce
        nonce = os.urandom(NONCE_SIZE)
        
        # Create AES-GCM cipher
        cipher = AESGCM(key)
        
        # Convert data to JSON and encode
        json_data = json.dumps(data).encode()
        
        # Encrypt the data
        ciphertext = cipher.encrypt(nonce, json_data, None)
        
        # Combine nonce and ciphertext
        return nonce + ciphertext
    finally:
        # Securely wipe the key from memory
        secure_memory_wipe(key)

def decrypt_data(encrypted: bytes, key: bytes) -> dict:
    """Decrypt data using AES-256-GCM with authentication"""
    try:
        # Split nonce and ciphertext
        nonce = encrypted[:NONCE_SIZE]
        ciphertext = encrypted[NONCE_SIZE:]
        
        # Create AES-GCM cipher
        cipher = AESGCM(key)
        
        # Decrypt the data
        decrypted = cipher.decrypt(nonce, ciphertext, None)
        
        # Parse JSON
        return json.loads(decrypted.decode())
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")
    finally:
        # Securely wipe the key from memory
        secure_memory_wipe(key)

def save_data(username: str, data: dict, key: bytes):
    """Save encrypted data with additional security measures"""
    user_manager = get_user_manager()
    db_path = user_manager.get_user_db_path(username)
    if not db_path:
        raise ValueError(f"No database path found for user {username}")
    
    try:
        # Add metadata for security
        data['_metadata'] = {
            'last_modified': datetime.utcnow().isoformat(),
            'version': '2.0',
            'encryption': 'AES-256-GCM',
            'iterations': SCRYPT_N,
            'memory_cost': SCRYPT_P,
            'parallelism': SCRYPT_P
        }
        
        # Encrypt the data
        encrypted_data = encrypt_data(data, key)
        
        # Write to a temporary file first
        temp_path = db_path + '.tmp'
        with open(temp_path, "wb") as f:
            f.write(encrypted_data)
        
        # Atomic rename for security
        os.replace(temp_path, db_path)
    finally:
        # Securely wipe sensitive data
        secure_memory_wipe(str(data))
        secure_memory_wipe(encrypted_data)

def load_data(username: str, key: bytes) -> dict:
    """Load and decrypt data with additional security checks"""
    user_manager = get_user_manager()
    db_path = user_manager.get_user_db_path(username)
    if not db_path:
        return {}
        
    try:
        with open(db_path, "rb") as f:
            encrypted_data = f.read()
        
        data = decrypt_data(encrypted_data, key)
        
        # Verify metadata
        if '_metadata' in data:
            metadata = data['_metadata']
            if metadata.get('encryption') != 'AES-256-GCM':
                raise ValueError("Database uses outdated encryption")
            if metadata.get('iterations', 0) < SCRYPT_N:
                raise ValueError("Database uses outdated security parameters")
            if metadata.get('memory_cost', 0) < SCRYPT_P:
                raise ValueError("Database uses outdated memory parameters")
        
        return data
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
        return {}
    finally:
        # Securely wipe sensitive data
        secure_memory_wipe(encrypted_data)

# Session management
class SessionManager:
    def __init__(self):
        self.last_activity = time.time()
        self.is_locked = False
    
    def update_activity(self):
        self.last_activity = time.time()
        self.is_locked = False
    
    def check_session(self):
        if time.time() - self.last_activity > SESSION_TIMEOUT:
            self.is_locked = True
            return False
        return True
    
    def lock(self):
        self.is_locked = True
    
    def unlock(self):
        self.is_locked = False
        self.update_activity()

# Create a global session manager
session_manager = SessionManager()

# Debug counters
def create_manager_tab(parent, password_generator_func=None):
    frame = tb.Frame(parent, padding=10)
    frame.pack(fill="both", expand=True)
    
    # Initialize backup manager
    backup_manager = BackupManager(get_user_manager())
    
    # Debug counters and logging functions (must be defined before handlers)
    button_press_counts = {"login": 0, "logout": 0, "register": 0}

    def log_tabs(action):
        tab_texts = [notebook.tab(i, "text") for i in range(notebook.index("end"))]
        logger.info(f"[UI] {action} | Tabs: {tab_texts}")

    def log_button_press(name):
        button_press_counts[name] += 1
        logger.info(f"[UI] Button '{name}' pressed {button_press_counts[name]} times")

    # Add session check
    def check_session():
        if not session_manager.check_session():
            messagebox.showwarning("Session Expired", "Your session has expired. Please log in again.")
            logout()
        else:
            frame.after(1000, check_session)  # Check every second
    
    # Start session monitoring
    frame.after(1000, check_session)
    
    # Create a notebook for login/register and password manager
    notebook = tb.Notebook(frame)
    notebook.pack(fill="both", expand=True)

    # Create login/register frame
    auth_frame = tb.Frame(notebook, padding=10)
    notebook.add(auth_frame, text="Login/Register")

    # Create password manager frame
    manager_frame = tb.Frame(notebook, padding=10)
    # Don't add the manager frame to notebook initially
    # It will be added after successful login/registration

    # Add account import/export tab using the new module, but keep reference to its index
    def get_tab_texts():
        return [notebook.tab(i, "text") for i in range(notebook.index("end"))]

    def ensure_tab_order():
        desired_order = ["Login/Register", "Password Manager", "Account Import/Export"]
        current_tabs = get_tab_texts()
        for idx, tab_name in enumerate(desired_order):
            if tab_name in current_tabs:
                current_idx = current_tabs.index(tab_name)
                if current_idx != idx:
                    notebook.insert(idx, notebook.tabs()[current_idx])

    # Ensure Import/Export tab exists
    if "Account Import/Export" not in get_tab_texts():
        account_tab = create_account_import_export_tab(notebook, get_user_manager())

    # Variables
    username_var = tb.StringVar()
    password_var = tb.StringVar()
    data = {}  # {category: {site: {username, password}}}
    key = None
    user_manager = get_user_manager()
    selected_category = tb.StringVar()

    def is_logged_in():
        return bool(key)

    def show_manager():
        # Remove the Password Manager tab if present
        for i in range(notebook.index("end")):
            if notebook.tab(i, "text") == "Password Manager":
                notebook.forget(i)
                break
        # Remove the Login/Register tab if present
        for i in range(notebook.index("end")):
            if notebook.tab(i, "text") == "Login/Register":
                notebook.forget(i)
                break
        # Add the manager tab if not already present
        if "Password Manager" not in get_tab_texts():
            add_manager_tab()
        ensure_tab_order()
        update_category_menu()
        selected_category.set('All')
        load_tree()
        # Always select the Password Manager tab by name
        for i in range(notebook.index("end")):
            if notebook.tab(i, "text") == "Password Manager":
                notebook.select(i)
                break
        # Pass current username to Import/Export tab if possible
        for i in range(notebook.index("end")):
            if notebook.tab(i, "text") == "Account Import/Export":
                tab_frame = notebook.nametowidget(notebook.tabs()[i])
                if hasattr(tab_frame, 'set_logged_in_user'):
                    tab_frame.set_logged_in_user(username_var.get())
                break
        # Fallback: if no tabs, add and select Login/Register
        if notebook.index("end") == 0:
            notebook.add(auth_frame, text="Login/Register")
            notebook.select(0)

    def update_category_menu():
        categories = list(data.keys())
        if not categories:
            categories = ["Default"]
            data["Default"] = {}
        category_menu['values'] = categories
        selected_category.set(categories[0])

    def load_tree():
        tree.delete(*tree.get_children())
        cat = selected_category.get() if 'selected_category' in locals() else None
        if cat == 'All':
            for category, entries in data.items():
                for site, creds in entries.items():
                    if isinstance(creds, dict) and 'username' in creds:
                        tree.insert("", "end", values=(site, creds["username"]))
                    else:
                        logger.warning(f"Skipping malformed entry for site {site}: {creds}")
        elif cat in data:
            for site, creds in data[cat].items():
                if isinstance(creds, dict) and 'username' in creds:
                    tree.insert("", "end", values=(site, creds["username"]))
                else:
                    logger.warning(f"Skipping malformed entry for site {site}: {creds}")

    def add_category():
        cat = simpledialog.askstring("New Category", "Enter category name")
        if not cat:
            return
        if cat not in data:
            data[cat] = {}
            update_category_menu()
            load_tree()

    def delete_category():
        cat = selected_category.get()
        if cat in data and messagebox.askyesno("Delete Category", f"Delete category '{cat}' and all its entries?"):
            del data[cat]
            update_category_menu()
            load_tree()

    def hide_entry_form():
        entry_form_frame.pack_forget()
        username_entry.delete(0, 'end')
        password_entry.delete(0, 'end')
        new_cat_var.set("")
        service_var.set("")
        service_name_entry.delete(0, 'end')
        new_cat_entry.pack_forget()
        new_cat_entry.config(state="disabled")
    def show_entry_form():
        update_service_menu()
        service_var.set(list(data.keys())[0] if data else "")
        entry_form_frame.pack(fill="x", pady=5)
        new_cat_entry.config(state="disabled")
    def add_entry_submit():
        if not is_logged_in():
            messagebox.showerror("Not Logged In", "Please log in first.")
            return
        cat = service_var.get()
        if cat == '+ New Category':
            cat = new_cat_var.get().strip()
            if not cat:
                messagebox.showerror("Missing Info", "Please enter a new category name.")
                return
            if cat not in data:
                data[cat] = {}
            update_category_menu()
        site = service_name_entry.get().strip()
        uname = username_entry.get().strip()
        pword = password_entry.get().strip()
        if not site or not uname or not pword:
            messagebox.showerror("Missing Info", "Please fill out all fields.")
            return
        if cat not in data:
            data[cat] = {}
        data[cat][site] = {"username": uname, "password": pword}
        save_data(username_var.get(), data, key)
        load_tree()
        hide_entry_form()

    # Entry form for adding new service (initially hidden)
    entry_form_frame = tb.Frame(manager_frame)
    # First row: fields
    fields_frame = tb.Frame(entry_form_frame)
    fields_frame.pack(fill="x")
    tb.Label(fields_frame, text="Category:").pack(side="left", padx=2)
    def get_category_options():
        cats = list(data.keys())
        cats = [c for c in cats if c]  # Remove empty string keys if any
        if 'All' not in cats:
            cats.insert(0, 'All')
        if '+ New Category' not in cats:
            cats.append('+ New Category')
        return cats
    service_var = tb.StringVar()
    service_menu = tb.Combobox(fields_frame, textvariable=service_var, state="readonly", width=16)
    service_menu['values'] = get_category_options()
    service_menu.pack(side="left", padx=2)
    new_cat_var = tb.StringVar()
    new_cat_entry = tb.Entry(fields_frame, textvariable=new_cat_var, width=14)
    def update_service_menu():
        service_menu['values'] = get_category_options()
    def on_service_selected(event=None):
        if service_var.get() == '+ New Category':
            new_cat_entry.pack(side="left", padx=2)
            new_cat_entry.config(state="normal")
            new_cat_entry.focus_set()
        else:
            new_cat_entry.pack_forget()
            new_cat_var.set("")
            new_cat_entry.config(state="disabled")
    service_menu.bind('<<ComboboxSelected>>', on_service_selected)
    tb.Label(fields_frame, text="Service:").pack(side="left", padx=2)
    service_name_entry = tb.Entry(fields_frame, width=18)
    service_name_entry.pack(side="left", padx=2)
    tb.Label(fields_frame, text="Username:").pack(side="left", padx=2)
    username_entry = tb.Entry(fields_frame, width=18)
    username_entry.pack(side="left", padx=2)
    tb.Label(fields_frame, text="Password:").pack(side="left", padx=2)
    password_entry = tb.Entry(fields_frame, width=18, show="•")
    password_entry.pack(side="left", padx=2)
    # Second row: buttons
    buttons_frame = tb.Frame(entry_form_frame)
    buttons_frame.pack(fill="x", pady=(2, 0))
    tb.Button(buttons_frame, text="Add", command=add_entry_submit).pack(side="left", padx=2)
    tb.Button(buttons_frame, text="Cancel", command=hide_entry_form).pack(side="left", padx=2)
    hide_entry_form()

    def delete_entry():
        if not is_logged_in():
            messagebox.showerror("Not Logged In", "Please log in first.")
            return
        selected = tree.selection()
        cat = selected_category.get()
        if not selected or cat not in data:
            return
        for item in selected:
            site = tree.item(item, "values")[0]
            tree.delete(item)
            if site in data[cat]:
                del data[cat][site]
        save_data(username_var.get(), data, key)

    def login():
        nonlocal key, data
        username = username_var.get()
        password = password_var.get()
        if not username or not password:
            messagebox.showerror("Error", "Username and password required")
            return

        success, message = user_manager.authenticate_user(username, password)
        if success:
            db_path = user_manager.get_user_db_path(username)
            if db_path:
                try:
                    with open(db_path, 'rb') as f:
                        encrypted_data = f.read()
                    user_data = user_manager.user_registry["users"][username]
                    salt = base64.b64decode(user_data["salt"])
                    n = user_data.get("iterations", 16384)
                    r = user_data.get("memory_cost", 8)
                    p = user_data.get("parallelism", 4)
                    dklen = 32
                    logger.info(f"[login] Attempting login for {username} with salt={user_data['salt']}, n={n}, r={r}, p={p}, db_path={db_path}, file_size={os.path.getsize(db_path)} bytes")
                    # Check scrypt parameters for safety
                    if n > 2**15 or r > 16 or p > 8:
                        password_entry.config(bootstyle="danger")
                        login_error_label.config(text=f"Scrypt parameters too high for this system (n={n}, r={r}, p={p}). Please re-export your account with lower settings.", foreground="red")
                        return
                    key = hashlib.scrypt(
                        password.encode(), salt=salt, n=n, r=r, p=p, dklen=dklen
                    )
                    logger.info(f"[login] Derived decryption key: {base64.b64encode(key).decode()}")
                    data = decrypt_data(encrypted_data, key)
                    # Ensure at least one category exists
                    if not data:
                        data["Default"] = {}
                    show_manager()
                except Exception as e:
                    password_entry.config(bootstyle="danger")
                    login_error_label.config(text=f"Failed to load database: {str(e)}", foreground="red")
                    return
        else:
            password_entry.config(bootstyle="danger")
            login_error_label.config(text=message, foreground="red")

    def register():
        log_button_press("register")
        username = username_var.get()
        password = password_var.get()
        logger.info(f"Register button clicked for username: {username}")
        if not username or not password:
            messagebox.showerror("Error", "Username and password required")
            return

        def do_register():
            logger.info(f"Starting user_manager.create_user for {username}")
            success, message = user_manager.create_user(username, password)
            logger.info(f"user_manager.create_user finished for {username} with success={success}, message={message}")
            def on_done():
                if success:
                    messagebox.showinfo("Success", "Account created successfully. Please log in.")
                else:
                    messagebox.showerror("Error", message)
                register_button.config(state="normal")
            frame.after(0, on_done)

        register_button.config(state="disabled")
        threading.Thread(target=do_register, daemon=True).start()

    # Login/Register UI
    auth_container = tb.Frame(auth_frame)
    auth_container.pack(expand=True, fill="both", pady=20)

    # Title
    tb.Label(
        auth_container,
        text="Hoodie Password Manager",
        font=("Arial", 14, "bold")
    ).pack(pady=(0, 20))

    # Username
    tb.Label(auth_container, text="Username:").pack(pady=5)
    tb.Entry(auth_container, textvariable=username_var, width=30).pack(pady=5)

    # Password
    tb.Label(auth_container, text="Password:").pack(pady=5)
    password_entry = tb.Entry(auth_container, textvariable=password_var, show="•", width=30)
    password_entry.pack(pady=5)
    # Error label for login feedback
    login_error_label = tb.Label(auth_container, text="", foreground="red")
    login_error_label.pack(pady=(0, 5))

    def reset_login_error(event=None):
        password_entry.config(bootstyle="")
        login_error_label.config(text="")
    password_entry.bind("<Key>", reset_login_error)

    # Buttons
    button_frame = tb.Frame(auth_container)
    button_frame.pack(pady=20)

    tb.Button(
        button_frame,
        text="Login",
        command=login,
        style="Accent.TButton"
    ).pack(side="left", padx=5)

    register_button = tb.Button(
        button_frame,
        text="Register",
        command=register
    )
    register_button.pack(side="left", padx=5)

    # Category selection and management UI
    category_frame = tb.Frame(manager_frame)
    category_frame.pack(fill="x", pady=5)
    tb.Label(category_frame, text="Category:").pack(side="left")
    category_menu = tb.Combobox(category_frame, textvariable=selected_category, state="readonly", width=20)
    category_menu.pack(side="left", padx=5)
    tb.Button(category_frame, text="Add Category", command=add_category).pack(side="left", padx=2)
    tb.Button(category_frame, text="Delete Category", command=delete_category).pack(side="left", padx=2)

    # Tree view for passwords
    tree = tb.Treeview(manager_frame, columns=("Site", "Username"), show="headings")
    tree.heading("Site", text="Service")
    tree.heading("Username", text="Username")
    tree.pack(fill="both", expand=True, pady=10)

    # Buttons for password manager
    manager_button_frame = tb.Frame(manager_frame)
    manager_button_frame.pack(fill="x")

    tb.Button(
        manager_button_frame,
        text="Add Entry",
        command=show_entry_form
    ).pack(side="left", padx=5)

    tb.Button(
        manager_button_frame,
        text="Delete Entry",
        command=delete_entry
    ).pack(side="left", padx=5)

    tb.Button(
        manager_button_frame,
        text="Logout",
        command=lambda: [notebook.forget(0), notebook.add(auth_frame, text="Login/Register")]
    ).pack(side="right", padx=5)

    # Update category menu when switching to manager
    selected_category.trace_add('write', lambda *args: load_tree())

    # Add logout function for session expiration
    def logout():
        nonlocal key, data
        key = None
        data = {}
        # Remove only the Password Manager tab if present
        pm_index = None
        for i in range(notebook.index("end")):
            if notebook.tab(i, "text") == "Password Manager":
                pm_index = i
                break
        if pm_index is not None:
            notebook.forget(pm_index)
        # Ensure Login/Register tab is present
        if "Login/Register" not in get_tab_texts():
            notebook.insert(0, auth_frame, text="Login/Register")
        ensure_tab_order()
        # Always select the Login/Register tab by name
        for i in range(notebook.index("end")):
            if notebook.tab(i, "text") == "Login/Register":
                notebook.select(i)
                break
        # Fallback: if no tabs, add and select Login/Register
        if notebook.index("end") == 0:
            notebook.add(auth_frame, text="Login/Register")
            notebook.select(0)
        messagebox.showinfo("Logged Out", "You have been logged out due to inactivity.")

    # Add password manager frame to the notebook before the account import/export tab
    def add_manager_tab():
        # Insert the manager tab just before the last tab (Account Import/Export)
        notebook.insert(notebook.index('end') - 1, manager_frame, text="Password Manager")

    def create_backup():
        """Create a backup of the current user's database"""
        if not is_logged_in():
            messagebox.showerror("Error", "Please log in first")
            return
            
        success, result = backup_manager.create_backup(get_user_manager().current_user)
        if success:
            messagebox.showinfo("Success", f"Backup created successfully at:\n{result}")
        else:
            messagebox.showerror("Error", result)
            
    def restore_backup():
        """Restore a backup for the current user"""
        if not is_logged_in():
            messagebox.showerror("Error", "Please log in first")
            return
            
        success, backups = backup_manager.list_backups(get_user_manager().current_user)
        if not success:
            messagebox.showerror("Error", backups)
            return
            
        if not backups:
            messagebox.showinfo("Info", "No backups found")
            return
            
        # Create a dialog to select backup
        dialog = tb.Toplevel(frame)
        dialog.title("Select Backup to Restore")
        dialog.geometry("400x300")
        
        # Create a listbox with backups
        listbox = tb.Listbox(dialog)
        listbox.pack(fill="both", expand=True, padx=10, pady=10)
        
        for backup in backups:
            listbox.insert(tb.END, f"{backup['timestamp']} (v{backup['version']})")
            
        def do_restore():
            selection = listbox.curselection()
            if not selection:
                messagebox.showerror("Error", "Please select a backup to restore")
                return
                
            backup = backups[selection[0]]
            if messagebox.askyesno("Confirm Restore", 
                "Are you sure you want to restore this backup?\n"
                "A backup of your current database will be created first."):
                success, result = backup_manager.restore_backup(
                    get_user_manager().current_user,
                    backup["path"]
                )
                if success:
                    messagebox.showinfo("Success", result)
                    dialog.destroy()
                    load_tree()  # Refresh the tree view
                else:
                    messagebox.showerror("Error", result)
                    
        # Add buttons
        button_frame = tb.Frame(dialog)
        button_frame.pack(fill="x", padx=10, pady=5)
        
        tb.Button(
            button_frame,
            text="Restore",
            command=do_restore,
            style="Accent.TButton"
        ).pack(side="right", padx=5)
        
        tb.Button(
            button_frame,
            text="Cancel",
            command=dialog.destroy
        ).pack(side="right", padx=5)
        
    def manage_backups():
        """Open backup management dialog"""
        if not is_logged_in():
            messagebox.showerror("Error", "Please log in first")
            return
            
        success, backups = backup_manager.list_backups(get_user_manager().current_user)
        if not success:
            messagebox.showerror("Error", backups)
            return
            
        # Create a dialog to manage backups
        dialog = tb.Toplevel(frame)
        dialog.title("Manage Backups")
        dialog.geometry("500x400")
        
        # Create a treeview for backups
        columns = ("Timestamp", "Version", "Path")
        tree = tb.Treeview(dialog, columns=columns, show="headings")
        
        # Set column headings
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=100)
            
        tree.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Add backups to treeview
        for backup in backups:
            tree.insert("", "end", values=(
                backup["timestamp"],
                backup["version"],
                backup["path"]
            ))
            
        def delete_selected():
            selection = tree.selection()
            if not selection:
                messagebox.showerror("Error", "Please select a backup to delete")
                return
                
            item = tree.item(selection[0])
            backup_path = item["values"][2]
            
            if messagebox.askyesno("Confirm Delete", 
                "Are you sure you want to delete this backup?"):
                success, result = backup_manager.delete_backup(backup_path)
                if success:
                    tree.delete(selection[0])
                    messagebox.showinfo("Success", result)
                else:
                    messagebox.showerror("Error", result)
                    
        def restore_selected():
            selection = tree.selection()
            if not selection:
                messagebox.showerror("Error", "Please select a backup to restore")
                return
                
            item = tree.item(selection[0])
            backup_path = item["values"][2]
            
            if messagebox.askyesno("Confirm Restore", 
                "Are you sure you want to restore this backup?\n"
                "A backup of your current database will be created first."):
                success, result = backup_manager.restore_backup(
                    get_user_manager().current_user,
                    backup_path
                )
                if success:
                    messagebox.showinfo("Success", result)
                    dialog.destroy()
                    load_tree()  # Refresh the tree view
                else:
                    messagebox.showerror("Error", result)
                    
        # Add buttons
        button_frame = tb.Frame(dialog)
        button_frame.pack(fill="x", padx=10, pady=5)
        
        tb.Button(
            button_frame,
            text="Restore Selected",
            command=restore_selected,
            style="Accent.TButton"
        ).pack(side="right", padx=5)
        
        tb.Button(
            button_frame,
            text="Delete Selected",
            command=delete_selected
        ).pack(side="right", padx=5)
        
        tb.Button(
            button_frame,
            text="Close",
            command=dialog.destroy
        ).pack(side="right", padx=5)
        
    # Add backup buttons to the manager frame
    backup_frame = tb.Frame(manager_frame)
    backup_frame.pack(fill="x", padx=5, pady=5)
    
    tb.Button(
        backup_frame,
        text="Create Backup",
        command=create_backup
    ).pack(side="left", padx=5)
    
    tb.Button(
        backup_frame,
        text="Restore Backup",
        command=restore_backup
    ).pack(side="left", padx=5)
    
    tb.Button(
        backup_frame,
        text="Manage Backups",
        command=manage_backups
    ).pack(side="left", padx=5)

    return frame

if __name__ == "__main__":
    root = tb.Window(themename="darkly")
    notebook = tb.Notebook(root)
    notebook.pack(fill="both", expand=True)

    tab = tb.Frame(notebook)
    notebook.add(tab, text="Password Manager")
    create_manager_tab(tab)

    root.mainloop()
