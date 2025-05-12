import os
import json
import base64
import hashlib
import secrets
import time
import tkinter as tk
from cryptography.fernet import Fernet # type: ignore
from cryptography.hazmat.primitives import hashes # type: ignore
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # type: ignore


class UserManager:
    """Manages multiple users for the password manager"""
    
    def __init__(self):
        # Create users directory if it doesn't exist
        self.users_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "users")
        if not os.path.exists(self.users_dir):
            os.makedirs(self.users_dir)
            
        self.user_registry_path = os.path.join(self.users_dir, "user_registry.json")
        self.current_user = None
        self.load_user_registry()
        
    def load_user_registry(self):
        """Load the user registry file or create a new one if it doesn't exist"""
        if os.path.exists(self.user_registry_path):
            try:
                with open(self.user_registry_path, 'r') as f:
                    # The registry only contains non-sensitive data like usernames and DB locations
                    self.user_registry = json.load(f)
            except Exception as e:
                print(f"Error loading user registry: {e}")
                self.user_registry = {"users": {}}
        else:
            # Create a new registry
            self.user_registry = {"users": {}}
            self.save_user_registry()
            
    def save_user_registry(self):
        """Save the user registry to disk"""
        try:
            with open(self.user_registry_path, 'w') as f:
                json.dump(self.user_registry, f, indent=2)
        except Exception as e:
            print(f"Error saving user registry: {e}")
            
    def user_exists(self, username):
        """Check if a user exists in the registry"""
        return username in self.user_registry["users"]
        
    def create_user(self, username, password):
        """
        Create a new user with the given username and password
        
        Returns:
            bool: True if user was created successfully, False otherwise
        """
        if self.user_exists(username):
            return False, "Username already exists"
            
        # Generate a salt for this user
        salt = secrets.token_bytes(16)
        
        # Hash the password with the salt
        hashed_password = self._hash_password(password, salt)
        
        # Generate a unique ID for the user's database
        user_id = base64.urlsafe_b64encode(os.urandom(8)).decode('utf-8')
        
        # Create user's database directory
        user_db_dir = os.path.join(self.users_dir, user_id)
        if not os.path.exists(user_db_dir):
            os.makedirs(user_db_dir)
            
        # Default database path for this user
        db_path = os.path.join(user_db_dir, "password_db.enc")
        
        # Add user to registry
        self.user_registry["users"][username] = {
            "user_id": user_id,
            "password_hash": base64.b64encode(hashed_password).decode('utf-8'),
            "salt": base64.b64encode(salt).decode('utf-8'),
            "db_path": db_path,
            "created_at": time.time(),
            "last_login": None
        }
        
        self.save_user_registry()

        # Create an empty encrypted database file for the new user
        try:
            from .password_manager import encrypt_data
            from cryptography.fernet import Fernet
            key, _ = self.generate_encryption_key(password, salt)
            empty_data = encrypt_data({}, key)
            with open(db_path, "wb") as f:
                f.write(empty_data)
        except Exception as e:
            print(f"Error creating initial database for user {username}: {e}")

        return True, "User created successfully"
        
    def authenticate_user(self, username, password):
        """
        Authenticate a user with the given username and password
        
        Returns:
            bool: True if authentication was successful, False otherwise
        """
        if not self.user_exists(username):
            return False, "User does not exist"
            
        user_data = self.user_registry["users"][username]
        stored_hash = base64.b64decode(user_data["password_hash"])
        salt = base64.b64decode(user_data["salt"])
        
        # Hash the provided password with the stored salt
        password_hash = self._hash_password(password, salt)
        
        # Compare with stored hash
        if password_hash == stored_hash:
            # Update last login time
            self.user_registry["users"][username]["last_login"] = time.time()
            self.save_user_registry()
            self.current_user = username
            return True, "Authentication successful"
        else:
            return False, "Incorrect password"
            
    def get_user_db_path(self, username=None):
        """Get the database path for a user"""
        if username is None:
            username = self.current_user
            
        if not username or not self.user_exists(username):
            return None
            
        return self.user_registry["users"][username]["db_path"]
        
    def change_password(self, username, current_password, new_password):
        """Change a user's password"""
        auth_success, message = self.authenticate_user(username, current_password)
        if not auth_success:
            return False, message
            
        # Generate a new salt
        salt = secrets.token_bytes(16)
        
        # Hash the new password with the salt
        hashed_password = self._hash_password(new_password, salt)
        
        # Update the registry
        self.user_registry["users"][username]["password_hash"] = base64.b64encode(hashed_password).decode('utf-8')
        self.user_registry["users"][username]["salt"] = base64.b64encode(salt).decode('utf-8')
        
        self.save_user_registry()
        return True, "Password changed successfully"
        
    def delete_user(self, username, password):
        """Delete a user and their database"""
        auth_success, message = self.authenticate_user(username, password)
        if not auth_success:
            return False, message
            
        user_data = self.user_registry["users"][username]
        user_db_dir = os.path.dirname(user_data["db_path"])
        
        # Remove user database directory
        try:
            if os.path.exists(user_data["db_path"]):
                os.remove(user_data["db_path"])
                
            if os.path.exists(user_db_dir):
                # Remove any other files in the directory
                for filename in os.listdir(user_db_dir):
                    file_path = os.path.join(user_db_dir, filename)
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                        
                # Remove the directory
                os.rmdir(user_db_dir)
        except Exception as e:
            print(f"Error deleting user files: {e}")
            
        # Remove user from registry
        del self.user_registry["users"][username]
        
        if self.current_user == username:
            self.current_user = None
            
        self.save_user_registry()
        return True, "User deleted successfully"
        
    def export_user_database(self, username, password, export_path):
        """Export a user's database to a specified location"""
        auth_success, message = self.authenticate_user(username, password)
        if not auth_success:
            return False, message
            
        user_data = self.user_registry["users"][username]
        source_path = user_data["db_path"]
        
        if not os.path.exists(source_path):
            return False, "Database does not exist"
            
        try:
            # Create export directory if it doesn't exist
            export_dir = os.path.dirname(export_path)
            if not os.path.exists(export_dir):
                os.makedirs(export_dir)
                
            # Create a metadata file with necessary user info (excluding password hash)
            metadata = {
                "username": username,
                "user_id": user_data["user_id"],
                "created_at": user_data["created_at"],
                "exported_at": time.time()
            }
            
            metadata_path = os.path.join(export_dir, "hoodie_db_metadata.json")
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
                
            # Copy the database file
            with open(source_path, 'rb') as src:
                with open(export_path, 'wb') as dst:
                    dst.write(src.read())
                    
            return True, "Database exported successfully"
        except Exception as e:
            return False, f"Error exporting database: {e}"
            
    def import_user_database(self, username, password, import_path, metadata_path=None):
        """Import a database for an existing user"""
        if not self.user_exists(username):
            return False, "User does not exist"
            
        auth_success, message = self.authenticate_user(username, password)
        if not auth_success:
            return False, message
            
        if not os.path.exists(import_path):
            return False, "Import file does not exist"
            
        user_data = self.user_registry["users"][username]
        destination_path = user_data["db_path"]
        
        try:
            # Backup existing database if it exists
            if os.path.exists(destination_path):
                backup_path = destination_path + ".backup"
                with open(destination_path, 'rb') as src:
                    with open(backup_path, 'wb') as dst:
                        dst.write(src.read())
                        
            # Copy the imported database file
            with open(import_path, 'rb') as src:
                with open(destination_path, 'wb') as dst:
                    dst.write(src.read())
                    
            return True, "Database imported successfully"
        except Exception as e:
            return False, f"Error importing database: {e}"
            
    def list_users(self):
        """Get a list of all usernames"""
        return list(self.user_registry["users"].keys())
        
    def get_user_info(self, username):
        """Get information about a user (excluding sensitive data)"""
        if not self.user_exists(username):
            return None
            
        user_data = self.user_registry["users"][username]
        return {
            "username": username,
            "user_id": user_data["user_id"],
            "created_at": user_data["created_at"],
            "last_login": user_data["last_login"]
        }
        
    def logout(self):
        """Log out the current user"""
        self.current_user = None
        
    def _hash_password(self, password, salt):
        """Hash a password with the given salt using PBKDF2"""
        # Use PBKDF2 with a high number of iterations for security
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode('utf-8'))
        
    def generate_encryption_key(self, password, salt=None):
        """Generate an encryption key from a password and salt"""
        if salt is None:
            salt = secrets.token_bytes(16)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
        return key, salt
    
    def is_logged_in(self):
        return self.current_user is not None


class LoginDialog:
    """Dialog for user login and registration"""
    
    def __init__(self, parent, user_manager, on_success_callback=None):
        self.parent = parent
        self.user_manager = user_manager
        self.on_success_callback = on_success_callback
        self.create_dialog()
        
    def create_dialog(self):
        """Create the login dialog UI"""
        import tkinter as tk
        from tkinter import ttk
        
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Password Manager Login")
        self.dialog.geometry("400x350")
        self.dialog.resizable(False, False)
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.update_idletasks()
        width = self.dialog.winfo_width()
        height = self.dialog.winfo_height()
        x = (self.dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (height // 2)
        self.dialog.geometry(f"{width}x{height}+{x}+{y}")
        
        # Main frame
        main_frame = ttk.Frame(self.dialog, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(main_frame, text="Hoodie Password Manager", font=("Arial", 14, "bold")).pack(pady=(0, 20))
        
        # Notebook for login/register tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Login tab
        login_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(login_frame, text="Login")
        
        # Register tab
        register_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(register_frame, text="Register")
        
        # Login form
        ttk.Label(login_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.login_username = ttk.Entry(login_frame, width=30)
        self.login_username.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(login_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.login_password = ttk.Entry(login_frame, width=30, show="•")
        self.login_password.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # User selection dropdown
        ttk.Label(login_frame, text="Or select user:").grid(row=2, column=0, sticky=tk.W, pady=5)
        users = self.user_manager.list_users()
        self.user_var = tk.StringVar()
        self.user_dropdown = ttk.Combobox(login_frame, textvariable=self.user_var, values=users, state="readonly", width=27)
        self.user_dropdown.grid(row=2, column=1, sticky=tk.W, pady=5)
        self.user_dropdown.bind("<<ComboboxSelected>>", self.on_user_selected)
        
        # Error message
        self.login_error = ttk.Label(login_frame, text="", foreground="red")
        self.login_error.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # Login button
        login_button = ttk.Button(login_frame, text="Login", command=self.login)
        login_button.grid(row=4, column=0, columnspan=2, pady=15)
        
        # Register form
        ttk.Label(register_frame, text="New Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.register_username = ttk.Entry(register_frame, width=30)
        self.register_username.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(register_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.register_password = ttk.Entry(register_frame, width=30, show="•")
        self.register_password.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(register_frame, text="Confirm Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.register_confirm = ttk.Entry(register_frame, width=30, show="•")
        self.register_confirm.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # Error message
        self.register_error = ttk.Label(register_frame, text="", foreground="red")
        self.register_error.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # Register button
        register_button = ttk.Button(register_frame, text="Create Account", command=self.register)
        register_button.grid(row=4, column=0, columnspan=2, pady=15)
        
        # Import/Export buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Import Database", command=self.import_database).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export Database", command=self.export_database).pack(side=tk.LEFT, padx=5)
        
        # Cancel button
        ttk.Button(main_frame, text="Cancel", command=self.dialog.destroy).pack(pady=5)
        
    def on_user_selected(self, event):
        """Fill the username field when a user is selected from dropdown"""
        self.login_username.delete(0, tk.END) # type: ignore
        self.login_username.insert(0, self.user_var.get())
        
    def login(self):
        """Attempt to log in with provided credentials"""
        username = self.login_username.get().strip()
        password = self.login_password.get()
        
        if not username or not password:
            self.login_error.config(text="Please enter both username and password")
            return
            
        success, message = self.user_manager.authenticate_user(username, password)
        if success:
            if self.on_success_callback:
                # Get the database path for this user
                db_path = self.user_manager.get_user_db_path(username)
                self.on_success_callback(username, password, db_path)
            self.dialog.destroy()
        else:
            self.login_error.config(text=message)
            
    def register(self):
        """Register a new user"""
        username = self.register_username.get().strip()
        password = self.register_password.get()
        confirm = self.register_confirm.get()
        
        if not username or not password:
            self.register_error.config(text="Please enter both username and password")
            return
            
        if password != confirm:
            self.register_error.config(text="Passwords do not match")
            return
            
        if len(password) < 8:
            self.register_error.config(text="Password must be at least 8 characters")
            return
            
        success, message = self.user_manager.create_user(username, password)
        if success:
            self.register_error.config(text="")
            # Switch to login tab and prefill username
            self.notebook.select(0)
            self.login_username.delete(0, tk.END) # type: ignore
            self.login_username.insert(0, username)
            # Update user dropdown
            users = self.user_manager.list_users()
            self.user_dropdown.config(values=users)
        else:
            self.register_error.config(text=message)
            
    def import_database(self):
        """Import a database from an external location"""
        import tkinter.filedialog as filedialog
        import tkinter.messagebox as messagebox
        
        username = self.login_username.get().strip()
        password = self.login_password.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password first")
            return
            
        if not self.user_manager.user_exists(username):
            messagebox.showerror("Error", "User does not exist. Please register first.")
            return
            
        file_path = filedialog.askopenfilename(
            title="Import Password Database",
            filetypes=[("Encrypted Database", "*.enc"), ("All Files", "*.*")]
        )
        
        if file_path:
            success, message = self.user_manager.import_user_database(username, password, file_path)
            if success:
                messagebox.showinfo("Success", "Database imported successfully")
            else:
                messagebox.showerror("Error", message)
                
    def export_database(self):
        """Export the database to an external location"""
        import tkinter.filedialog as filedialog
        import tkinter.messagebox as messagebox
        
        username = self.login_username.get().strip()
        password = self.login_password.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password first")
            return
            
        if not self.user_manager.user_exists(username):
            messagebox.showerror("Error", "User does not exist")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Export Password Database",
            defaultextension=".enc",
            filetypes=[("Encrypted Database", "*.enc"), ("All Files", "*.*")]
        )
        
        if file_path:
            success, message = self.user_manager.export_user_database(username, password, file_path)
            if success:
                messagebox.showinfo("Success", "Database exported successfully")
            else:
                messagebox.showerror("Error", message)


def create_login_dialog(parent, on_success_callback=None):
    """Create and display the login dialog"""
    user_manager = UserManager()
    return LoginDialog(parent, user_manager, on_success_callback)
    
    
def get_user_manager():
    """Get a UserManager instance"""
    return UserManager()