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
    user_manager = get_user_manager()
    db_path = user_manager.get_user_db_path(username)
    if not db_path:
        raise ValueError(f"No database path found for user {username}")
    
    encrypted_data = encrypt_data(data, key)
    with open(db_path, "wb") as f:
        f.write(encrypted_data)

def load_data(username: str, key: bytes) -> dict:
    user_manager = get_user_manager()
    db_path = user_manager.get_user_db_path(username)
    if not db_path:
        return {}
        
    try:
        with open(db_path, "rb") as f:
            encrypted_data = f.read()
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
    data = {}  # {category: {site: {username, password}}}
    key = None
    user_manager = get_user_manager()
    selected_category = tb.StringVar()

    def is_logged_in():
        return bool(key)

    def show_manager():
        notebook.forget(0)
        notebook.add(manager_frame, text="Password Manager")
        update_category_menu()
        selected_category.set('All')
        load_tree()

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
                    tree.insert("", "end", values=(site, creds["username"]))
        elif cat in data:
            for site, creds in data[cat].items():
                tree.insert("", "end", values=(site, creds["username"]))

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
                    key = user_manager.generate_encryption_key(password, salt)[0]
                    data = decrypt_data(encrypted_data, key)
                    # Ensure at least one category exists
                    if not data:
                        data["Default"] = {}
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

    return frame

if __name__ == "__main__":
    root = tb.Window(themename="darkly")
    notebook = tb.Notebook(root)
    notebook.pack(fill="both", expand=True)

    tab = tb.Frame(notebook)
    notebook.add(tab, text="Password Manager")
    create_manager_tab(tab)

    root.mainloop()
