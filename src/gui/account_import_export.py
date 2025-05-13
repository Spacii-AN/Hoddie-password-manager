import ttkbootstrap as tb

def create_account_import_export_tab(notebook, user_manager):
    account_frame = tb.Frame(notebook, padding=10)
    notebook.add(account_frame, text="Account Import/Export")

    # Centering frame for all content
    center_frame = tb.Frame(account_frame)
    center_frame.place(relx=0.5, rely=0.5, anchor="center")

    # Instruction label at the top
    tb.Label(center_frame, text="Export or Import your account for backup or migration.", font=("Arial", 12)).pack(pady=(0, 18))

    # Username and password entry fields stacked vertically
    username_var = tb.StringVar()
    password_var = tb.StringVar()

    username_entry = tb.Entry(center_frame, textvariable=username_var, width=32, font=("Arial", 11))
    username_entry.pack(pady=5)
    username_entry.insert(0, "Username")
    def clear_username_placeholder(event):
        if username_entry.get() == "Username":
            username_entry.delete(0, tb.END)
    def restore_username_placeholder(event):
        if not username_entry.get():
            username_entry.insert(0, "Username")
    username_entry.bind("<FocusIn>", clear_username_placeholder)
    username_entry.bind("<FocusOut>", restore_username_placeholder)

    password_entry = tb.Entry(center_frame, textvariable=password_var, show="", width=32, font=("Arial", 11))
    password_entry.pack(pady=5)
    password_entry.insert(0, "Password")
    def clear_password_placeholder(event):
        if password_entry.get() == "Password":
            password_entry.delete(0, tb.END)
            password_entry.config(show="*")
    def restore_password_placeholder(event):
        if not password_entry.get():
            password_entry.insert(0, "Password")
            password_entry.config(show="")
    password_entry.bind("<FocusIn>", clear_password_placeholder)
    password_entry.bind("<FocusOut>", restore_password_placeholder)

    # Status label for feedback
    status_label = tb.Label(center_frame, text="", foreground="red", font=("Arial", 10))
    status_label.pack(pady=(5, 0))

    # Buttons side by side, below the fields
    button_frame = tb.Frame(center_frame)
    button_frame.pack(pady=18)
    tb.Button(button_frame, text="Export Account", command=lambda: export_account_ui(), style="Accent.TButton", width=16).pack(side=tb.LEFT, padx=8)
    tb.Button(button_frame, text="Import Account", command=lambda: import_account_ui(), width=16).pack(side=tb.LEFT, padx=8)

    def export_account_ui():
        username = username_var.get().strip()
        password = password_var.get()
        if username == "Username" or not username or password == "Password" or not password:
            status_label.config(text="Please enter both username and password.", foreground="red")
            return
        from tkinter import filedialog
        file_path = filedialog.asksaveasfilename(
            title="Export Account",
            defaultextension=".enc",
            filetypes=[("Encrypted Export", "*.enc"), ("All Files", "*.*")]
        )
        if not file_path:
            status_label.config(text="Export cancelled.", foreground="red")
            return
        success, msg = user_manager.export_user_account(username, password, file_path)
        if success:
            status_label.config(text=msg, foreground="green")
        else:
            status_label.config(text=msg, foreground="red")

    def import_account_ui():
        password = password_var.get()
        if password == "Password" or not password:
            status_label.config(text="Please enter your password.", foreground="red")
            return
        from tkinter import filedialog
        file_path = filedialog.askopenfilename(
            title="Import Account",
            filetypes=[("Encrypted Export", "*.enc"), ("All Files", "*.*")]
        )
        if not file_path:
            status_label.config(text="Import cancelled.", foreground="red")
            return
        success, msg = user_manager.import_user_account(file_path, password)
        if success:
            status_label.config(text=msg, foreground="green")
        else:
            status_label.config(text=msg, foreground="red")

    return account_frame 