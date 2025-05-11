import os
import base64
import sqlite3
import hashlib
import json
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class SecurePasswordDatabase:
    def __init__(self, db_path, username, master_password):
        self.db_path = db_path
        self.username = username
        self.master_password = master_password
        self.connection = None
        self.fernet = None

    def connect(self):
        self.connection = sqlite3.connect(self.db_path)
        self._init_tables()
        return self._verify_or_create_user()

    def _init_tables(self):
        cursor = self.connection.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS users ("
                       "username TEXT PRIMARY KEY,"
                       "salt BLOB NOT NULL,"
                       "key_hash TEXT NOT NULL)")
        cursor.execute("CREATE TABLE IF NOT EXISTS passwords ("
                       "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                       "username TEXT NOT NULL,"
                       "site TEXT NOT NULL,"
                       "enc_data TEXT NOT NULL,"
                       "created_at TEXT NOT NULL,"
                       "FOREIGN KEY (username) REFERENCES users(username))")
        self.connection.commit()

    def _derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _verify_or_create_user(self):
        cursor = self.connection.cursor()
        cursor.execute("SELECT salt, key_hash FROM users WHERE username = ?", (self.username,))
        result = cursor.fetchone()
        if result:
            salt, stored_key_hash = result
            key = self._derive_key(self.master_password, salt)
            self.fernet = Fernet(key)
            if hashlib.sha256(key).hexdigest() == stored_key_hash:
                return True, "User authenticated"
            else:
                return False, "Incorrect master password"
        else:
            salt = os.urandom(16)
            key = self._derive_key(self.master_password, salt)
            key_hash = hashlib.sha256(key).hexdigest()
            cursor.execute("INSERT INTO users (username, salt, key_hash) VALUES (?, ?, ?)",
                           (self.username, salt, key_hash))
            self.connection.commit()
            self.fernet = Fernet(key)
            return True, "New user created"

    def add_entry(self, site, username, password):
        encrypted = self.fernet.encrypt(json.dumps({
            "username": username,
            "password": password
        }).encode()).decode()
        cursor = self.connection.cursor()
        cursor.execute("INSERT INTO passwords (username, site, enc_data, created_at) "
                       "VALUES (?, ?, ?, ?)",
                       (self.username, site, encrypted, datetime.now().isoformat()))
        self.connection.commit()
        return True

    def get_entries(self):
        cursor = self.connection.cursor()
        cursor.execute("SELECT site, enc_data, created_at FROM passwords WHERE username = ?", (self.username,))
        rows = cursor.fetchall()
        entries = []
        for site, enc_data, created_at in rows:
            try:
                decrypted = self.fernet.decrypt(enc_data.encode()).decode()
                data = json.loads(decrypted)
                entries.append({
                    "site": site,
                    "username": data["username"],
                    "password": data["password"],
                    "created_at": created_at
                })
            except (InvalidToken, json.JSONDecodeError):
                continue
        return entries

    def close(self):
        if self.connection:
            self.connection.close()
            self.connection = None
