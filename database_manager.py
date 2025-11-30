"""
Handles all SQLite interactions for users, logs, and dynamic config settings.
"""
import sqlite3
import hashlib
import time
from config import Config

class DatabaseManager:
    """Handles all SQLite interactions for users and activity logging, including SMTP settings."""
    
    def __init__(self, db_name):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self._setup_db()

    def _setup_db(self):
        """Creates the necessary tables if they do not exist."""
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
        """)
        # Table to store dynamic SMTP sender credentials
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS config_settings (
                setting_name TEXT PRIMARY KEY,
                setting_value TEXT NOT NULL
            )
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def check_registration(self):
        """Checks if a master user account exists."""
        self.cursor.execute("SELECT COUNT(*) FROM users")
        return self.cursor.fetchone()[0] > 0

    def register_user(self, email, password):
        """Hashes the password and stores the new user."""
        try:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            self.cursor.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, hashed_password))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def store_smtp_settings(self, email, password):
        """Stores the sender's email and app password securely in the configuration table."""
        self.cursor.execute("INSERT OR REPLACE INTO config_settings (setting_name, setting_value) VALUES (?, ?)", 
                            ('SMTP_EMAIL', email))
        self.cursor.execute("INSERT OR REPLACE INTO config_settings (setting_name, setting_value) VALUES (?, ?)", 
                            ('SMTP_PASSWORD', password))
        self.conn.commit()

    def get_smtp_settings(self):
        """Retrieves the sender's email and app password from the database."""
        self.cursor.execute("SELECT setting_value FROM config_settings WHERE setting_name = 'SMTP_EMAIL'")
        email = self.cursor.fetchone()
        self.cursor.execute("SELECT setting_value FROM config_settings WHERE setting_name = 'SMTP_PASSWORD'")
        password = self.cursor.fetchone()
        
        return {
            'email': email[0] if email else None, 
            'password': password[0] if password else None
        }

    def get_user_email(self):
        """Retrieves the registered user's email."""
        self.cursor.execute("SELECT email FROM users LIMIT 1")
        result = self.cursor.fetchone()
        return result[0] if result else None

    def verify_login(self, email, password):
        """Verifies the email and password hash."""
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.cursor.execute("SELECT * FROM users WHERE email = ? AND password_hash = ?", (email, hashed_password))
        return self.cursor.fetchone() is not None

    def log_activity(self, event):
        """Records a timestamped event into the activity log."""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        self.cursor.execute("INSERT INTO logs (timestamp, event) VALUES (?, ?)", (timestamp, event))
        self.conn.commit()
        return f"[{timestamp}] {event}"

    def get_logs(self):
        """Fetches all activity logs (Newest first)."""
        self.cursor.execute("SELECT timestamp, event FROM logs ORDER BY id DESC")
        return [f"[{ts}] {evt}" for ts, evt in self.cursor.fetchall()]

    def clear_logs(self):
        """Deletes all entries from the activity log table."""
        self.cursor.execute("DELETE FROM logs")
        self.conn.commit()

    def close(self):
        """Closes the database connection."""
        self.conn.close()