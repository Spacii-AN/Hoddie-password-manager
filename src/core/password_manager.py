import os
import base64
import hashlib
import json
from datetime import datetime
from tkinter import messagebox, simpledialog, filedialog
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from .user_manager import get_user_manager

# Utility functions

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data: dict, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(json.dumps(data).encode())

def decrypt_data(encrypted: bytes, key: bytes) -> dict:
    f = Fernet(key)
    decrypted = f.decrypt(encrypted).decode()
    return json.loads(decrypted)

def save_data(username: str, data: dict, key: bytes):
    encrypted_data = encrypt_data(data, key)
    encoded_data = base64.b64encode(encrypted_data).decode("utf-8")
    with open(f"{username}_vault.dat", "w") as f:
        f.write(encoded_data)

def load_data(username: str, key: bytes) -> dict:
    try:
        with open(f"{username}_vault.dat", "r") as f:
            encoded_data = f.read()
        encrypted_data = base64.b64decode(encoded_data)
        return decrypt_data(encrypted_data, key)
    except (FileNotFoundError, InvalidToken, json.JSONDecodeError):
        return {}

def create_manager_tab(parent, password_generator_func=None):
    frame = tb.Frame(parent, padding=10)
    frame.pack(fill="both", expand=True)

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

    # Variables
    username_var = tb.StringVar()
    password_var = tb.StringVar()
    data = {}
    key = None
    user_manager = get_user_manager()

    def is_logged_in():
        return bool(key)

    def show_manager():
        # Remove the auth frame and add the manager frame
        notebook.forget(0)  # Remove auth frame
        notebook.add(manager_frame, text="Password Manager")
        load_tree()

    def login():
        nonlocal key, data
        username = username_var.get()
        password = password_var.get()
        if not username or not password:
            messagebox.showerror("Error", "Username and password required")
            return

        success, message = user_manager.authenticate_user(username, password)
        if success:
            # Get the database path for this user
            db_path = user_manager.get_user_db_path(username)
            if db_path:
                try:
                    with open(db_path, 'rb') as f:
                        encrypted_data = f.read()
                    key = user_manager.generate_encryption_key(password)[0]
                    data = decrypt_data(encrypted_data, key)
                    show_manager()
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to load database: {str(e)}")
        else:
            messagebox.showerror("Error", message)

    def register():
        username = username_var.get()
        password = password_var.get()
        if not username or not password:
            messagebox.showerror("Error", "Username and password required")
            return

        success, message = user_manager.create_user(username, password)
        if success:
            messagebox.showinfo("Success", "Account created successfully. Please log in.")
        else:
            messagebox.showerror("Error", message)

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
    tb.Entry(auth_container, textvariable=password_var, show="•", width=30).pack(pady=5)

    # Buttons
    button_frame = tb.Frame(auth_container)
    button_frame.pack(pady=20)

    tb.Button(
        button_frame,
        text="Login",
        command=login,
        style="Accent.TButton"
    ).pack(side="left", padx=5)

    tb.Button(
        button_frame,
        text="Register",
        command=register
    ).pack(side="left", padx=5)

    # Password Manager UI
    def load_tree():
        for item in tree.get_children():
            tree.delete(item)
        for site, creds in data.items():
            tree.insert("", "end", values=(site, creds["username"]))

    def add_entry():
        if not is_logged_in():
            messagebox.showerror("Not Logged In", "Please log in first.")
            return
        site = simpledialog.askstring("Site", "Enter site name")
        uname = simpledialog.askstring("Username", "Enter username")
        pword = simpledialog.askstring("Password", "Enter password")
        if not site or not uname or not pword:
            return
        data[site] = {"username": uname, "password": pword}
        save_data(username_var.get(), data, key)
        load_tree()

    def delete_entry():
        if not is_logged_in():
            messagebox.showerror("Not Logged In", "Please log in first.")
            return
        selected = tree.selection()
        if not selected:
            return
        for item in selected:
            site = tree.item(item, "values")[0]
            tree.delete(item)
            if site in data:
                del data[site]
        save_data(username_var.get(), data, key)

    # Tree view for passwords
    tree = tb.Treeview(manager_frame, columns=("Site", "Username"), show="headings")
    tree.heading("Site", text="Site")
    tree.heading("Username", text="Username")
    tree.pack(fill="both", expand=True, pady=10)

    # Buttons for password manager
    manager_button_frame = tb.Frame(manager_frame)
    manager_button_frame.pack(fill="x")

    tb.Button(
        manager_button_frame,
        text="Add Entry",
        command=add_entry
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

    return frame

if __name__ == "__main__":
    root = tb.Window(themename="darkly")
    notebook = tb.Notebook(root)
    notebook.pack(fill="both", expand=True)

    tab = tb.Frame(notebook)
    notebook.add(tab, text="Password Manager")
    create_manager_tab(tab)

    root.mainloop()
