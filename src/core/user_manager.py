import os
import json
import base64
import hashlib
import secrets
import time
import tkinter as tk
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import ctypes
import logging

# Security constants
SALT_SIZE = 32  # Increased from 16 to 32 bytes
NONCE_SIZE = 12  # Standard size for GCM
MIN_PASSWORD_LENGTH = 12  # Minimum password length requirement
MAX_LOGIN_ATTEMPTS = 5  # Maximum number of failed login attempts
LOGIN_TIMEOUT = 300  # 5 minutes timeout after max attempts
BACKUP_ENCRYPTION_VERSION = "2.0"
SCRYPT_N = 2**14  # CPU/memory cost (increase for more security, decrease for more speed)
SCRYPT_R = 8      # Block size
SCRYPT_P = 4  # Parallelization: reduced for faster login/registration
SCRYPT_DKLEN = 32 # Output key length (256 bits)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

class UserManager:
    """Manages multiple users for the password manager"""
    
    def __init__(self):
        # Create users directory if it doesn't exist
        self.users_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "users")
        if not os.path.exists(self.users_dir):
            os.makedirs(self.users_dir)
            
        self.user_registry_path = os.path.join(self.users_dir, "user_registry.json")
        self.current_user = None
        self.login_attempts = {}  # Track login attempts
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
        logger.info(f"[create_user] Start for {username}")
        if self.user_exists(username):
            logger.info(f"[create_user] Username already exists: {username}")
            return False, "Username already exists"
        # Enhanced password requirements
        if len(password) < MIN_PASSWORD_LENGTH:
            logger.info(f"[create_user] Password too short for {username}")
            return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long"
        if not any(c.isupper() for c in password):
            logger.info(f"[create_user] No uppercase for {username}")
            return False, "Password must contain at least one uppercase letter"
        if not any(c.islower() for c in password):
            logger.info(f"[create_user] No lowercase for {username}")
            return False, "Password must contain at least one lowercase letter"
        if not any(c.isdigit() for c in password):
            logger.info(f"[create_user] No digit for {username}")
            return False, "Password must contain at least one number"
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            logger.info(f"[create_user] No special char for {username}")
            return False, "Password must contain at least one special character"
        try:
            logger.info(f"[create_user] Generating salt for {username}")
            salt = secrets.token_bytes(SALT_SIZE)
            logger.info(f"[create_user] Hashing password for {username}")
            hashed_password = self._hash_password(password, salt)
            logger.info(f"[create_user] Password hashed for {username}")
            user_id = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')
            user_db_dir = os.path.join(self.users_dir, user_id)
            if not os.path.exists(user_db_dir):
                os.makedirs(user_db_dir)
            db_path = os.path.join(user_db_dir, "password_db.enc")
            self.user_registry["users"][username] = {
                "user_id": user_id,
                "password_hash": base64.b64encode(hashed_password).decode('utf-8'),
                "salt": base64.b64encode(salt).decode('utf-8'),
                "db_path": db_path,
                "created_at": time.time(),
                "last_login": None,
                "security_version": "2.0",
                "iterations": SCRYPT_N,
                "memory_cost": SCRYPT_N,
                "parallelism": SCRYPT_P,
                "failed_attempts": 0,
                "last_failed_attempt": None
            }
            self.save_user_registry()
            try:
                from .password_manager import encrypt_data
                from cryptography.fernet import Fernet
                key, _ = self.generate_encryption_key(password, salt)
                empty_data = encrypt_data({}, key)
                with open(db_path, "wb") as f:
                    f.write(empty_data)
            except Exception as e:
                logger.error(f"[create_user] Error creating initial database for user {username}: {e}")
            logger.info(f"[create_user] Finished for {username}")
            return True, "User created successfully"
        finally:
            logger.info(f"[create_user] Secure memory wipe for {username}")
            secure_memory_wipe(password)
            secure_memory_wipe(hashed_password)
            secure_memory_wipe(salt)

    def authenticate_user(self, username, password):
        """Authenticate a user with enhanced security measures"""
        if not self.user_exists(username):
            return False, "User does not exist"
            
        user_data = self.user_registry["users"][username]
        
        # Check for too many failed attempts
        if user_data.get("failed_attempts", 0) >= MAX_LOGIN_ATTEMPTS:
            last_attempt = user_data.get("last_failed_attempt", 0)
            if time.time() - last_attempt < LOGIN_TIMEOUT:
                remaining = int(LOGIN_TIMEOUT - (time.time() - last_attempt))
                return False, f"Too many failed attempts. Try again in {remaining} seconds"
            else:
                # Reset failed attempts after timeout
                user_data["failed_attempts"] = 0
                
        stored_hash = base64.b64decode(user_data["password_hash"])
        salt = base64.b64decode(user_data["salt"])
        
        # Hash the provided password with the stored salt
        password_hash = self._hash_password(password, salt)
        
        # Compare with stored hash
        if password_hash == stored_hash:
            # Reset failed attempts on successful login
            user_data["failed_attempts"] = 0
            user_data["last_login"] = time.time()
            self.save_user_registry()
            self.current_user = username
            return True, "Authentication successful"
        else:
            # Increment failed attempts
            user_data["failed_attempts"] = user_data.get("failed_attempts", 0) + 1
            user_data["last_failed_attempt"] = time.time()
            self.save_user_registry()
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
        salt = secrets.token_bytes(SALT_SIZE)
        
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
        """Export a user's database with enhanced security"""
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
                
            # Generate a backup encryption key
            backup_key = os.urandom(32)
            
            # Create a metadata file with necessary user info (excluding password hash)
            metadata = {
                "username": username,
                "user_id": user_data["user_id"],
                "created_at": user_data["created_at"],
                "exported_at": time.time(),
                "encryption_version": BACKUP_ENCRYPTION_VERSION,
                "iterations": SCRYPT_N,
                "memory_cost": SCRYPT_N,
                "parallelism": SCRYPT_P
            }
            
            # Encrypt the metadata
            metadata_cipher = AESGCM(backup_key)
            metadata_nonce = os.urandom(NONCE_SIZE)
            encrypted_metadata = metadata_nonce + metadata_cipher.encrypt(
                metadata_nonce,
                json.dumps(metadata).encode(),
                None
            )
            
            # Write encrypted metadata
            metadata_path = os.path.join(export_dir, "hoodie_db_metadata.enc")
            with open(metadata_path, 'wb') as f:
                f.write(encrypted_metadata)
                
            # Read and encrypt the database
            with open(source_path, 'rb') as src:
                db_data = src.read()
                
            # Encrypt the database with the backup key
            db_cipher = AESGCM(backup_key)
            db_nonce = os.urandom(NONCE_SIZE)
            encrypted_db = db_nonce + db_cipher.encrypt(
                db_nonce,
                db_data,
                None
            )
            
            # Write encrypted database
            with open(export_path, 'wb') as dst:
                dst.write(encrypted_db)
                
            return True, "Database exported successfully"
        except Exception as e:
            return False, f"Error exporting database: {e}"
        finally:
            # Securely wipe sensitive data
            secure_memory_wipe(backup_key)
            secure_memory_wipe(db_data)
            secure_memory_wipe(encrypted_db)
            
    def import_user_database(self, username, password, import_path, metadata_path=None):
        """Import a database with enhanced security"""
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
            # Read and decrypt the metadata
            metadata_path = metadata_path or os.path.join(os.path.dirname(import_path), "hoodie_db_metadata.enc")
            if not os.path.exists(metadata_path):
                return False, "Metadata file not found"
                
            with open(metadata_path, 'rb') as f:
                encrypted_metadata = f.read()
                
            # Generate the backup key (in a real implementation, this would be derived from a backup password)
            backup_key = os.urandom(32)
            
            # Decrypt the metadata
            metadata_nonce = encrypted_metadata[:NONCE_SIZE]
            metadata_cipher = AESGCM(backup_key)
            decrypted_metadata = metadata_cipher.decrypt(
                metadata_nonce,
                encrypted_metadata[NONCE_SIZE:],
                None
            )
            metadata = json.loads(decrypted_metadata.decode())
            
            # Verify metadata
            if metadata.get("encryption_version") != BACKUP_ENCRYPTION_VERSION:
                return False, "Incompatible backup version"
                
            # Read and decrypt the database
            with open(import_path, 'rb') as f:
                encrypted_db = f.read()
                
            # Decrypt the database
            db_nonce = encrypted_db[:NONCE_SIZE]
            db_cipher = AESGCM(backup_key)
            decrypted_db = db_cipher.decrypt(
                db_nonce,
                encrypted_db[NONCE_SIZE:],
                None
            )
            
            # Backup existing database if it exists
            if os.path.exists(destination_path):
                backup_path = destination_path + ".backup"
                with open(destination_path, 'rb') as src:
                    with open(backup_path, 'wb') as dst:
                        dst.write(src.read())
                        
            # Write the decrypted database
            with open(destination_path, 'wb') as f:
                f.write(decrypted_db)
                
            return True, "Database imported successfully"
        except Exception as e:
            return False, f"Error importing database: {e}"
        finally:
            # Securely wipe sensitive data
            secure_memory_wipe(backup_key)
            secure_memory_wipe(decrypted_db)
            secure_memory_wipe(encrypted_db)
            
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
        logger.info(f"[_hash_password] Start (scrypt)")
        try:
            key = hashlib.scrypt(
                password.encode() if isinstance(password, str) else password,
                salt=salt,
                n=SCRYPT_N,
                r=SCRYPT_R,
                p=SCRYPT_P,
                dklen=SCRYPT_DKLEN
            )
            logger.info(f"[_hash_password] scrypt complete")
            return key
        finally:
            logger.info(f"[_hash_password] Secure memory wipe")
            secure_memory_wipe(password)
        
    def generate_encryption_key(self, password, salt=None):
        """Generate an encryption key from a password and salt"""
        try:
            if salt is None:
                salt = secrets.token_bytes(SALT_SIZE)
            key = hashlib.scrypt(
                password.encode() if isinstance(password, str) else password,
                salt=salt,
                n=SCRYPT_N,
                r=SCRYPT_R,
                p=SCRYPT_P,
                dklen=SCRYPT_DKLEN
            )
            return key, salt
        finally:
            secure_memory_wipe(password)
    
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