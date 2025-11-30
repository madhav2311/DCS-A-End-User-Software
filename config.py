"""
Contains static configuration constants used across all modules.
"""

class Config:
    APP_NAME = "DCS Security Vault"
    DB_NAME = "dcs_security_vault.db"
    VAULT_FOLDER = "SECURE_VAULT"
    ENCRYPTED_EXTENSION = ".dcsenc"
    SALT = b'\x19\ed\x95\xbc\x10\x94\xf7\xa6\x80\x02\x71\x13\x11\x19\x90\x94'
    FILENAME_SEPARATOR = b'|DCS_FNAME_SEP|'
    LOG_FONT = ('Courier', 10)
    
    # SMTP Host/Port (These are typically fixed by the provider)
    SMTP_HOST = "smtp.gmail.com"
    SMTP_PORT = 465  # Use 465 for SSL/TLS