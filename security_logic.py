"""
Handles file encryption, decryption, and secure shredding.
Relies on cryptography library and key derivation.
"""
import os
import uuid
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from config import Config

class SecurityLogic:
    """Handles file encryption, decryption, and secure shredding."""

    def __init__(self, db_manager):
        self.db = db_manager
        self.fernet_key = None # Key set after successful login

    def set_master_key(self, master_password):
        """Derives a Fernet key from the master password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=Config.SALT,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        self.fernet_key = key
        
    def _get_cipher(self):
        """Returns the Fernet cipher instance."""
        if not self.fernet_key:
            raise ValueError("Encryption key is not set. Log in first.")
        return Fernet(self.fernet_key)

    def secure_shred(self, filepath):
        """
        Implements a 3-pass secure data destruction algorithm.
        """
        try:
            filesize = os.path.getsize(filepath)
        except OSError:
            # File may already be gone or path invalid
            return
        
        with open(filepath, 'r+b') as f:
            # Pass 1: Random data
            self.db.log_activity(f"Shredding pass 1/3 (Random Data) on: {filepath}")
            f.seek(0)
            f.write(os.urandom(filesize))
            f.flush()

            # Pass 2: Zeros
            self.db.log_activity(f"Shredding pass 2/3 (Zeros) on: {filepath}")
            f.seek(0)
            f.write(b'\x00' * filesize)
            f.flush()

            # Pass 3: More zeros
            self.db.log_activity(f"Shredding pass 3/3 (Zeros) on: {filepath}")
            f.seek(0)
            f.write(b'\x00' * filesize)
            f.flush()

        # Final step: Delete file
        os.remove(filepath)
        self.db.log_activity(f"SUCCESS: Securely Shredded and deleted file: {filepath}")
        return True

    def encrypt_file(self, source_path):
        """Encrypts a file, embeds the filename, and shreds the original source."""
        cipher = self._get_cipher()
        vault_path = os.path.join(Config.VAULT_FOLDER, f"{uuid.uuid4()}{Config.ENCRYPTED_EXTENSION}")

        if not os.path.exists(Config.VAULT_FOLDER):
            os.makedirs(Config.VAULT_FOLDER)
            self.db.log_activity(f"Created secure vault folder: {Config.VAULT_FOLDER}")

        # 1. Read, Embed Filename, Encrypt, Write to Vault
        with open(source_path, 'rb') as f:
            file_data = f.read()
        
        original_filename = os.path.basename(source_path).encode('utf-8')
        data_to_encrypt = original_filename + Config.FILENAME_SEPARATOR + file_data

        encrypted_data = cipher.encrypt(data_to_encrypt)
        
        with open(vault_path, 'wb') as f:
            f.write(encrypted_data)
        
        self.db.log_activity(f"SUCCESS: Encrypted '{os.path.basename(source_path)}' to: {os.path.basename(vault_path)}")
        
        # 2. Shred Original Source File (MANDATORY)
        self.secure_shred(source_path)
        return True

    def decrypt_file(self, vault_path, output_dir):
        """Decrypts a vault file, restores it using the embedded original filename, and shreds the vault file."""
        cipher = self._get_cipher()
        
        # 1. Read, Decrypt
        with open(vault_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data_with_name = cipher.decrypt(encrypted_data)
        
        # 2. Extract Original Filename and Write File
        try:
            original_filename_bytes, decrypted_data = decrypted_data_with_name.split(Config.FILENAME_SEPARATOR, 1)
            original_name = original_filename_bytes.decode('utf-8')
        except ValueError:
            raise Exception("Decryption failed or file metadata is corrupt. Are you using the correct master key?")
        
        output_path = os.path.join(output_dir, original_name)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
            
        self.db.log_activity(f"SUCCESS: Decrypted '{os.path.basename(vault_path)}' and restored original name '{original_name}' to: {output_path}")

        # 3. Shred Encrypted Vault Container (MANDATORY)
        self.secure_shred(vault_path)
        return True