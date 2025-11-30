"""
DCS Security Vault (Secure Desktop App)
Main application entry point and CustomTkinter GUI.
"""
import customtkinter as ctk
import os
import time
from tkinter import filedialog, messagebox
import tkinter as tk # Imported for tk.END in shredding reset

# Import modules
from config import Config
from database_manager import DatabaseManager
from security_logic import SecurityLogic
from auth_manager import AuthManager

class SecureVaultApp(ctk.CTk):
    
    def __init__(self):
        super().__init__()
        
        # --- Setup ---
        self.title(Config.APP_NAME)
        self.geometry("1000x750")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        # --- Instances ---
        self.db_manager = DatabaseManager(Config.DB_NAME)
        self.auth_manager = AuthManager(self.db_manager)
        self.security_logic = SecurityLogic(self.db_manager)

        # --- State Variables ---
        self.is_registered = self.db_manager.check_registration()
        self.is_logged_in = False
        self.is_shred_otp_verified = False
        self.current_user_email = ""
        self.master_password = None # Store password temporarily for key derivation

        # --- Layout ---
        self.grid_columnconfigure(0, weight=3) # Main Content Area
        self.grid_columnconfigure(1, weight=1) # Log Area
        self.grid_rowconfigure(0, weight=1)
        
        # --- Left Frame: Main Content ---
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)
        
        # --- Right Frame: Activity Log ---
        self.log_frame = ctk.CTkFrame(self)
        self.log_frame.grid(row=0, column=1, padx=(0, 20), pady=20, sticky="nsew")
        
        # FIX: Configure column 0 of the log frame to expand horizontally
        self.log_frame.grid_columnconfigure(0, weight=1) 
        
        self.log_frame.grid_rowconfigure(1, weight=1)
        self._setup_log_ui()

        # --- Initial Flow Control ---
        if self.is_registered:
            self._setup_login_ui()
        else:
            self._setup_registration_ui()

        # Update log at start
        self.update_log_display()

    # --- UI Helpers ---

    def _setup_log_ui(self):
        """Sets up the Activity Log panel with improved styling."""
        log_title = ctk.CTkLabel(self.log_frame, text="USER ACTIVITY LOG", font=ctk.CTkFont(size=14, weight="bold"))
        log_title.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="ew")

        # Increased width and better visual
        self.log_textbox = ctk.CTkTextbox(self.log_frame, width=350, font=Config.LOG_FONT, corner_radius=8, fg_color="#1e293b")
        self.log_textbox.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        self.log_textbox.configure(state="disabled")

        log_button_frame = ctk.CTkFrame(self.log_frame, fg_color="transparent")
        log_button_frame.grid(row=2, column=0, padx=10, pady=(5, 10), sticky="ew")
        log_button_frame.grid_columnconfigure((0, 1), weight=1)

        ctk.CTkButton(log_button_frame, text="Clear Log", command=self._clear_log, fg_color="#b91c1c", hover_color="#991b1b").grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        ctk.CTkButton(log_button_frame, text="Save Log (TXT)", command=self._save_log, fg_color="#15803d", hover_color="#16a34a").grid(row=0, column=1, padx=5, pady=5, sticky="ew")

    def update_log_display(self, new_event_message=None):
        """Refreshes the log display with the latest entries and scrolls to top."""
        self.log_textbox.configure(state="normal")
        self.log_textbox.delete("1.0", "end")
        
        logs = self.db_manager.get_logs()
        self.log_textbox.insert("end", "\n".join(logs))
        self.log_textbox.see("1.0") # Scroll to the beginning (newest log entry)
        self.log_textbox.configure(state="disabled")

    def _clear_log(self):
        """Clears the database log and updates the display."""
        if messagebox.askyesno("Confirm Clear", "Are you sure you want to permanently clear the entire activity log?"):
            self.db_manager.clear_logs()
            self.update_log_display(self.db_manager.log_activity("Log cleared by user."))

    def _save_log(self):
        """Saves the current log contents to a local .txt file."""
        filepath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")], initialfile="DCS_Activity_Log.txt")
        if filepath:
            try:
                logs = self.db_manager.get_logs()
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(f"--- {Config.APP_NAME} Activity Log ---\n")
                    f.write(f"Exported: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    f.write("\n".join(logs))
                self.update_log_display(self.db_manager.log_activity(f"Log successfully saved to {filepath}"))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save log file: {e}")
                self.update_log_display(self.db_manager.log_activity(f"FAILURE: Failed to save log file. Error: {e}"))

    def _clear_main_frame(self):
        """Destroys all widgets in the main content frame."""
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def _open_file(self, filepath=None, is_dir=False):
        """Opens a file or directory using the OS default viewer (cross-platform)."""
        target = filepath if filepath else Config.VAULT_FOLDER
        
        if not os.path.exists(target):
            if is_dir:
                os.makedirs(target, exist_ok=True)
            else:
                messagebox.showerror("Error", f"Path does not exist: {target}")
                return

        try:
            if os.name == 'nt':  # Windows
                os.startfile(target)
            elif os.uname().sysname == 'Darwin':  # macOS
                os.system(f'open "{target}"')
            else:  # Linux/others
                os.system(f'xdg-open "{target}"')
            
            self.db_manager.log_activity(f"SUCCESS: Opened OS viewer for: {target}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open OS viewer for {target}. Error: {e}")
            self.db_manager.log_activity(f"FAILURE: Could not open OS viewer for {target}.")
        finally:
            self.update_log_display()

    # --- Authentication Flow ---

    def _setup_registration_ui(self):
        """Initial UI for one-time user registration."""
        self._clear_main_frame()
        
        title = ctk.CTkLabel(self.main_frame, text="REGISTER TO DCS ", font=ctk.CTkFont(size=24, weight="bold"))
        title.pack(padx=20, pady=(40, 10))

        subtitle = ctk.CTkLabel(self.main_frame, text="Set up your account and the necessary email sender credentials.", text_color="#facc15")
        subtitle.pack(padx=20, pady=(0, 20))

        # --- User Credentials (Receives OTP) ---
        ctk.CTkLabel(self.main_frame, text="1. User Master Credentials").pack(pady=(10, 5))
        self.reg_email_entry = ctk.CTkEntry(self.main_frame, placeholder_text="Master Email ", width=350, height=40)
        self.reg_email_entry.pack(padx=20, pady=5)
        self.reg_pass_entry = ctk.CTkEntry(self.main_frame, placeholder_text="Master Password", show="*", width=350, height=40)
        self.reg_pass_entry.pack(padx=20, pady=5)
        self.reg_confirm_pass_entry = ctk.CTkEntry(self.main_frame, placeholder_text="Confirm Master Password", show="*", width=350, height=40)
        self.reg_confirm_pass_entry.pack(padx=20, pady=5)

        # --- SMTP Sender Credentials (Sends OTP) ---
        ctk.CTkLabel(self.main_frame, text="2. SMTP Sender Credentials").pack(pady=(15, 5))
        ctk.CTkLabel(self.main_frame, text="NOTE: Requires App-Specific Password for Gmail/Outlook.", font=ctk.CTkFont(size=10, slant="italic")).pack()
        
        self.sender_email_entry = ctk.CTkEntry(self.main_frame, placeholder_text="Sender Email (e.g., your_email@gmail.com)", width=350, height=40)
        self.sender_email_entry.pack(padx=20, pady=5)
        self.sender_app_pass_entry = ctk.CTkEntry(self.main_frame, placeholder_text="Sender App Password (NOT your main password)", show="*", width=350, height=40)
        self.sender_app_pass_entry.pack(padx=20, pady=5)

        # Register Button
        register_button = ctk.CTkButton(self.main_frame, text="Complete Registration & Configure SMTP", command=self._handle_registration, width=350, height=45, fg_color="#4ade80", hover_color="#10b981", text_color="black", font=ctk.CTkFont(weight="bold"))
        register_button.pack(padx=20, pady=30)
        
    def _handle_registration(self):
        """
        Processes the registration form and saves both user and SMTP configuration to DB.
        """
        email = self.reg_email_entry.get().strip()
        password = self.reg_pass_entry.get()
        confirm_password = self.reg_confirm_pass_entry.get()
        sender_email = self.sender_email_entry.get().strip()
        sender_app_pass = self.sender_app_pass_entry.get()

        if not (email and password and confirm_password and sender_email and sender_app_pass):
            messagebox.showerror("Error", "All fields (User and SMTP) are required.")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Master passwords do not match.")
            return
            
        # 1. Register User Master Account
        if self.db_manager.register_user(email, password):
            # 2. Store SMTP Sender Configuration
            self.db_manager.store_smtp_settings(sender_email, sender_app_pass)

            self.current_user_email = email
            self.master_password = password
            self.is_registered = True
            
            self.db_manager.log_activity(f"SUCCESS: Master account registered for {email} and SMTP configured.")
            messagebox.showinfo("Success", "Registration and SMTP configuration complete. Proceeding to 2FA Login.")
            
            # --- Transition to Login UI ---
            self._setup_login_ui()
            
            # Prefill credentials and proceed immediately to OTP request (Phase 1)
            self.login_pass_entry.delete(0, "end")
            self.login_pass_entry.insert(0, password)
            self._handle_credentials_check()

        else:
            self.db_manager.log_activity(f"FAILURE: Registration attempt failed for {email}.")
            messagebox.showerror("Error", "Registration failed. Email might already be registered.")
            
        self.update_log_display()

    def _setup_login_ui(self):
        """UI for the primary two-factor login flow."""
        self._clear_main_frame()
        
        # --- Enforce Single User Email ---
        registered_email = self.db_manager.get_user_email()
        if not registered_email:
            # If the database is somehow corrupted or empty, force re-registration
            self._setup_registration_ui()
            return

        # ----------------------------------------------------
        # IMPLEMENTING EMAIL MASKING FOR DISPLAY
        # ----------------------------------------------------
        masked_email = registered_email
        if registered_email and '@' in registered_email:
            username, domain = registered_email.split('@', 1)
            
            # Mask the username part (show first letter, mask the rest)
            if len(username) > 1:
                masked_username = username[0] + ('*' * (len(username) - 1))
            else:
                masked_username = '*' # Handle very short usernames
                
            masked_email = f"{masked_username}@{domain}"
        # ----------------------------------------------------
        # END MASKING
        # ----------------------------------------------------

        self.login_frame = ctk.CTkFrame(self.main_frame)
        self.login_frame.pack(padx=40, pady=60, fill="both", expand=False, ipadx=20, ipady=20)
        self.login_frame.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(self.login_frame, text="SECURE ACCESS LOGIN (2FA)", font=ctk.CTkFont(size=22, weight="bold"))
        title.pack(padx=20, pady=(30, 20))
        
        self.login_status_label = ctk.CTkLabel(self.login_frame, text="Enter master password to request OTP.", text_color="white")
        self.login_status_label.pack(padx=20, pady=(0, 10))
        
        # Phase 1: Email/Password
        # Email field is pre-filled and disabled
        self.login_email_entry = ctk.CTkEntry(self.login_frame, width=300, height=35)
        self.login_email_entry.insert(0, masked_email) # Use the masked email here
        self.login_email_entry.configure(state="disabled")
        self.login_email_entry.pack(padx=20, pady=10)
        
        self.login_pass_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Master Password", show="*", width=300, height=35)
        self.login_pass_entry.pack(padx=20, pady=10)
        
        self.login_btn = ctk.CTkButton(self.login_frame, text="1. Verify Credentials & Get OTP", command=self._handle_credentials_check, width=300, height=40)
        self.login_btn.pack(padx=20, pady=(20, 30))

        # Phase 2: OTP
        self.otp_entry = ctk.CTkEntry(self.login_frame, placeholder_text="6-Digit OTP", width=300, height=35, state="disabled")
        self.otp_entry.pack(padx=20, pady=10)
        
        self.otp_verify_btn = ctk.CTkButton(self.login_frame, text="2. Verify OTP & Log In", command=self._handle_login_otp_check, width=300, height=40, state="disabled", fg_color="#3b82f6")
        self.otp_verify_btn.pack(padx=20, pady=10)

    def _handle_credentials_check(self):
        """
        Step 1 of login: check credentials and execute OTP delivery (SMTP attempt).
        This path is taken when credentials ALREADY exist.
        """
        # Email is now fixed to the registered user
        email = self.db_manager.get_user_email()
        password = self.login_pass_entry.get()

        if not self.db_manager.verify_login(email, password):
            # --- SECURITY ALERT: FAILED LOGIN ---
            self.auth_manager.send_failed_login_alert(email)
            
            self.login_status_label.configure(text="Login Failed: Invalid master password.", text_color="red")
            self.db_manager.log_activity(f"FAILED: Login attempt failed for {email} (Incorrect Password)")
            self.update_log_display()
            self.login_pass_entry.delete(0, "end") # Clear password for security
            return
            
        # Credentials verified, proceed to key storage and OTP request
        self.current_user_email = email
        self.master_password = password
        
        # Disable inputs and update UI for OTP step
        self.login_pass_entry.configure(state="disabled")
        self.login_btn.configure(state="disabled", text="Sending OTP...")
        
        self.login_status_label.configure(text="Sending OTP...", text_color="yellow")
        self.update_idletasks() # Force UI update

        otp_result = self.auth_manager.send_otp_code(email)

        if otp_result['status'] == 'success':
            self.otp_entry.configure(state="normal")
            self.otp_verify_btn.configure(state="normal")
            self.login_btn.configure(text="OTP Sent!")
            self.login_status_label.configure(text=f"OTP sent. {otp_result['message']}", text_color="green")
            self.db_manager.log_activity(f"AUTH: OTP Sent successfully to {email}.")
            
            # Inform user about status
            messagebox.showinfo("OTP Status", 
                                "OTP has been sent to your registered email address. ")
        else:
            # Re-enable inputs on OTP send failure
            self.login_pass_entry.configure(state="normal")
            self.login_btn.configure(text="Send OTP Code", state="normal")
            self.login_status_label.configure(text=otp_result['message'], text_color="red")
            self.db_manager.log_activity(f"AUTH: OTP failed for {email}: {otp_result['message']}")
            
        self.update_log_display()
            
    def _handle_login_otp_check(self):
        """
        Step 2 of login: verify OTP.
        """
        user_otp = self.otp_entry.get()
        result = self.auth_manager.verify_otp_code(user_otp)
        
        if result['status']:
            self.is_logged_in = True
            
            # Key Derivation
            self.security_logic.set_master_key(self.master_password)
            self.master_password = None # Clear temporary password
            
            self.db_manager.log_activity(f"LOGIN: SUCCESS. User {self.current_user_email} granted session access.")
            messagebox.showinfo("Success", f"Login successful for {self.current_user_email}!")
            self._setup_vault_ui()
        else:
            self.login_status_label.configure(text="Invalid OTP. Try again.", text_color="red")
            self.db_manager.log_activity(f"LOGIN: FAILED. Invalid OTP entered by {self.current_user_email or 'unknown user'}.")
            self.otp_entry.delete(0, "end")
            self.update_log_display()

    # --- Vault UI (Post-Login) ---

    def _setup_vault_ui(self):
        """Sets up the main application UI with Crypto, Shred, and Log tabs."""
        self._clear_main_frame()
        
        # Header
        header_frame = ctk.CTkFrame(self.main_frame, height=50, fg_color="#1e293b", corner_radius=8)
        header_frame.pack(fill="x", padx=10, pady=(10, 0))
        
        logged_in_label = ctk.CTkLabel(header_frame, text=f"SECURE VAULT ACTIVE | User: {self.current_user_email}", 
                                       font=ctk.CTkFont(size=14, weight="bold"), text_color="#4ade80")
        logged_in_label.pack(side="left", padx=15, pady=8)
        
        logout_btn = ctk.CTkButton(header_frame, text="Log Out", command=self._handle_logout, fg_color="red", hover_color="#dc2626", width=80)
        logout_btn.pack(side="right", padx=10, pady=8)

        # TabView
        self.tabview = ctk.CTkTabview(self.main_frame, width=700, height=500, segmented_button_fg_color="#374151")
        self.tabview.pack(padx=20, pady=20, fill="both", expand=True)

        self.tabview.add("Cryptographic Operations")
        self.tabview.add("Secure Data Destruction")

        self._setup_crypto_tab(self.tabview.tab("Cryptographic Operations"))
        self._setup_shred_tab(self.tabview.tab("Secure Data Destruction"))


    def _handle_logout(self):
        """Resets application state and returns to login screen."""
        if messagebox.askyesno("Confirm Logout", "Are you sure you want to log out? All access will be revoked."):
            self.db_manager.log_activity(f"LOGOUT: SUCCESS. Session ended for {self.current_user_email}.")
            
            self.is_logged_in = False
            self.is_shred_otp_verified = False
            self.current_user_email = ""
            self.security_logic.fernet_key = None # Clear the key
            self.master_password = None
            
            self.update_log_display()
            self._setup_login_ui()

    # --- Cryptographic Operations Tab ---

    def _setup_crypto_tab(self, tab):
        """Sets up the UI for file encryption and decryption."""
        tab.grid_columnconfigure(0, weight=1)
        
        # --- ENCRYPT SECTION ---
        encrypt_frame = ctk.CTkFrame(tab)
        encrypt_frame.pack(fill="x", padx=20, pady=(20, 10))
        ctk.CTkLabel(encrypt_frame, text="ENCRYPT FILE (Plaintext to Vault)", font=ctk.CTkFont(size=16, weight="bold")).pack(padx=10, pady=10)
        
        # Input row
        input_row_e = ctk.CTkFrame(encrypt_frame, fg_color="transparent")
        input_row_e.pack(fill="x", padx=10, pady=5)
        input_row_e.grid_columnconfigure(0, weight=1)
        
        self.encrypt_path = ctk.CTkEntry(input_row_e, placeholder_text="Select plaintext file to encrypt...", height=35)
        self.encrypt_path.grid(row=0, column=0, padx=(0, 5), sticky="ew")
        
        ctk.CTkButton(input_row_e, text="Browse", command=lambda: self._select_file_path(self.encrypt_path), width=70).grid(row=0, column=1, padx=5)
        ctk.CTkButton(input_row_e, text="View File", command=lambda: self._open_file(self.encrypt_path.get()), width=80).grid(row=0, column=2, padx=(5, 0))
        
        ctk.CTkButton(encrypt_frame, text="ENCRYPT & SHRED ORIGINAL (IRREVERSIBLE)", command=self._handle_encrypt, fg_color="#3b82f6", hover_color="#2563eb", height=40).pack(pady=15, fill="x", padx=10)

        # --- DECRYPT SECTION ---
        decrypt_frame = ctk.CTkFrame(tab)
        decrypt_frame.pack(fill="x", padx=20, pady=20)
        ctk.CTkLabel(decrypt_frame, text="DECRYPT VAULT FILE (Restores Original Name)", font=ctk.CTkFont(size=16, weight="bold")).pack(padx=10, pady=10)

        # Input row
        input_row_d = ctk.CTkFrame(decrypt_frame, fg_color="transparent")
        input_row_d.pack(fill="x", padx=10, pady=5)
        input_row_d.grid_columnconfigure(0, weight=1)

        self.decrypt_path = ctk.CTkEntry(input_row_d, placeholder_text=f"Select {Config.ENCRYPTED_EXTENSION} file from {Config.VAULT_FOLDER}...", height=35)
        self.decrypt_path.grid(row=0, column=0, padx=(0, 5), sticky="ew")
        
        ctk.CTkButton(input_row_d, text="Browse", command=lambda: self._select_file_path(self.decrypt_path, filetypes=[("DCS Encrypted Files", f"*{Config.ENCRYPTED_EXTENSION}")], initialdir=os.path.abspath(Config.VAULT_FOLDER) if os.path.exists(Config.VAULT_FOLDER) else None), width=70).grid(row=0, column=1, padx=5)
        ctk.CTkButton(input_row_d, text="View Vault", command=lambda: self._open_file(is_dir=True), width=80).grid(row=0, column=2, padx=(5, 0))

        ctk.CTkButton(decrypt_frame, text="DECRYPT & SHRED VAULT FILE (IRREVERSIBLE)", command=self._handle_decrypt, fg_color="#f97316", hover_color="#ea580c", height=40).pack(pady=15, fill="x", padx=10)
    
    def _select_file_path(self, entry_widget, filetypes=None, initialdir=None):
        """Opens a file dialog and populates the entry field."""
        filepath = filedialog.askopenfilename(filetypes=filetypes if filetypes else [("All Files", "*.*")], initialdir=initialdir)
        if filepath:
            entry_widget.delete(0, "end")
            entry_widget.insert(0, filepath)
            
    def _handle_encrypt(self):
        """Triggers the encryption and shredding process."""
        source_path = self.encrypt_path.get()
        if not os.path.isfile(source_path):
            messagebox.showerror("Error", "Please select a valid file to encrypt.")
            return

        try:
            self.security_logic.encrypt_file(source_path)
            messagebox.showinfo("Success", f"File encrypted and original source securely destroyed!")
            self.encrypt_path.delete(0, "end")
        except Exception as e:
            self.db_manager.log_activity(f"FAILURE: Encryption failed. Error: {e}")
            messagebox.showerror("Error", f"Encryption failed. See log for details.")
        finally:
            self.update_log_display()

    def _handle_decrypt(self):
        """Triggers the decryption and vault file shredding process."""
        vault_path = self.decrypt_path.get()
        if not vault_path.endswith(Config.ENCRYPTED_EXTENSION) or not os.path.isfile(vault_path):
            messagebox.showerror("Error", f"Please select a valid {Config.ENCRYPTED_EXTENSION} file from the vault.")
            return
            
        output_dir = filedialog.askdirectory(title="Select Destination Folder for Decrypted File")
        if not output_dir:
            return

        try:
            self.security_logic.decrypt_file(vault_path, output_dir)
            messagebox.showinfo("Success", f"File decrypted and restored to original name in '{output_dir}'. Encrypted container securely destroyed!")
            self.decrypt_path.delete(0, "end")
        except Exception as e:
            # Catching cryptography.fernet.InvalidToken here would be ideal, but catching all is safer for desktop apps.
            self.db_manager.log_activity(f"FAILURE: Decryption failed. Error: {e}")
            messagebox.showerror("Decryption Failed", f"Decryption failed! This is often due to using the wrong master key, or a corrupt file. See log for details.")
        finally:
            self.update_log_display()

    # --- Secure Data Destruction Tab (Shredding) ---

    def _setup_shred_tab(self, tab):
        """Sets up the UI for direct secure shredding with mandatory 2FA."""
        tab.grid_columnconfigure(0, weight=1)
        
        shred_frame = ctk.CTkFrame(tab)
        shred_frame.pack(fill="x", padx=20, pady=(20, 10))
        ctk.CTkLabel(shred_frame, text="SECURE FILE DESTRUCTION ", font=ctk.CTkFont(size=16, weight="bold"), text_color="#f87171").pack(padx=10, pady=10)
        
        # File Selection
        file_selection_frame = ctk.CTkFrame(shred_frame, fg_color="transparent")
        file_selection_frame.pack(fill="x", padx=10, pady=10)
        file_selection_frame.grid_columnconfigure(0, weight=1)
        
        self.shred_path = ctk.CTkEntry(file_selection_frame, placeholder_text="Select file for permanent destruction...", height=35)
        self.shred_path.grid(row=0, column=0, padx=(0, 5), sticky="ew")
        
        ctk.CTkButton(file_selection_frame, text="Browse", command=lambda: self._select_file_path(self.shred_path), width=70).grid(row=0, column=1, padx=5)
        ctk.CTkButton(file_selection_frame, text="View File", command=lambda: self._open_file(self.shred_path.get()), width=80).grid(row=0, column=2, padx=(5, 0))

        # OTP Gate
        otp_gate_frame = ctk.CTkFrame(shred_frame, fg_color="transparent")
        otp_gate_frame.pack(pady=20)
        
        ctk.CTkLabel(otp_gate_frame, text="REQUIRES AUTHORIZATION", font=ctk.CTkFont(weight="bold"), text_color="red").pack(pady=(0, 10))
        self.shred_status_label_auth = ctk.CTkLabel(otp_gate_frame, text="Request OTP to authorize shredding.", text_color="white")
        self.shred_status_label_auth.pack(pady=(0, 10))

        
        self.shred_otp_entry = ctk.CTkEntry(otp_gate_frame, placeholder_text="OTP for Shredding", width=200, height=35, state="disabled")
        self.shred_otp_entry.pack(pady=5)
        
        self.shred_get_otp_btn = ctk.CTkButton(otp_gate_frame, text="1. Send Shredding OTP", command=self._handle_shred_otp_send, fg_color="#f59e0b", hover_color="#d97706", width=200)
        self.shred_get_otp_btn.pack(pady=5)
        
        self.shred_verify_otp_btn = ctk.CTkButton(otp_gate_frame, text="2. Verify Shredding OTP", command=self._handle_shred_otp_verify, state="disabled", fg_color="#10b981", hover_color="#059669", width=200)
        self.shred_verify_otp_btn.pack(pady=5)
        
        # Final Destroy Button
        self.shred_destroy_btn = ctk.CTkButton(shred_frame, text="DESTROY FILE SECURELY (3-PASS IRREVERSIBLE)", command=self._handle_shred, state="disabled", fg_color="#ef4444", hover_color="#dc2626", height=45)
        self.shred_destroy_btn.pack(padx=20, pady=(20, 30), fill="x")

    def _handle_shred_otp_send(self):
        """
        Initiates the 2nd OTP send for the shredding action (SMTP attempt).
        """
        if not self.shred_path.get() or not os.path.isfile(self.shred_path.get()):
            messagebox.showerror("Error", "Please select a valid file to shred first.")
            return

        # Reset UI state to unauthorized
        self.is_shred_otp_verified = False 
        self.shred_destroy_btn.configure(state="disabled")
        self.shred_get_otp_btn.configure(state="disabled", text="Sending...")
        self.shred_verify_otp_btn.configure(state="disabled")
        self.shred_otp_entry.configure(state="disabled")
        self.shred_status_label_auth.configure(text="Sending OTP...", text_color="yellow")
        self.update_idletasks()
        
        # Attempt SMTP send (or fall back to simulation)
        otp_result = self.auth_manager.send_otp_code(self.current_user_email)

        if otp_result['status'] == 'success':
            self.shred_otp_entry.configure(state="normal")
            self.shred_verify_otp_btn.configure(state="normal")
            self.shred_get_otp_btn.configure(state="disabled", text="Sent!")
            self.shred_status_label_auth.configure(text="OTP Sent. Enter Code to Enable Shred.", text_color="green")
            self.db_manager.log_activity(f"SHRED_AUTH: OTP Sent successfully to {self.current_user_email}.")
        else:
            self.shred_get_otp_btn.configure(state="normal", text="1. Send Shredding OTP")
            self.shred_status_label_auth.configure(text=f"OTP Failure: {otp_result['message']}", text_color="red")
            self.db_manager.log_activity(f"SHRED_AUTH: OTP Failed for {self.current_user_email}: {otp_result['message']}.")

        messagebox.showinfo("OTP Status", 
                            "OTP has been sent to your registered email address for shredding authorization. ")
        self.update_log_display()

    def _handle_shred_otp_verify(self):
        """
        Verifies the 2nd OTP for shredding.
        """
        user_otp = self.shred_otp_entry.get()
        result = self.auth_manager.verify_otp_code(user_otp)
        
        if result['status']:
            self.is_shred_otp_verified = True
            self.shred_status_label_auth.configure(text="VERIFIED! Shredding Enabled.", text_color="#38A169")
            self.shred_verify_otp_btn.configure(state="disabled")
            self.shred_otp_entry.configure(state="disabled")
            self.shred_get_otp_btn.configure(state="disabled")
            self.shred_destroy_btn.configure(state="normal") # ENABLE THE SHRED BUTTON
            self.db_manager.log_activity(f"SHRED_AUTH: Verified. Destruction authorized for {self.current_user_email}.")
        else:
            self.shred_status_label_auth.configure(text="Verification Failed. Invalid OTP.", text_color="red")
            self.shred_otp_entry.delete(0, tk.END)
            self.shred_destroy_btn.configure(state="disabled")
            self.db_manager.log_activity(f"SHRED_AUTH: Verification Failed. Invalid OTP entered.")
            
        self.update_log_display()

    def _handle_shred(self):
        """Performs the final 3-pass secure shredding operation."""
        if not self.is_shred_otp_verified:
            messagebox.showerror("Access Denied", "Shredding requires immediate 2FA confirmation. Please send and verify the OTP first.")
            return
            
        filepath = self.shred_path.get()
        if not os.path.isfile(filepath):
            messagebox.showerror("Error", "File not found or invalid path.")
            return

        if messagebox.askyesno("CONFIRM DESTRUCTION", f"WARNING: Are you absolutely sure you want to permanently destroy the file: {os.path.basename(filepath)}? This is irreversible."):
            try:
                self.security_logic.secure_shred(filepath)
                messagebox.showinfo("Destruction Complete", "File has been securely shredded (3-pass overwrite) and deleted.")
                self.shred_path.delete(0, "end")
                
                # Reset shredding state
                self.is_shred_otp_verified = False
                self.shred_destroy_btn.configure(state="disabled")
                self.shred_get_otp_btn.configure(state="normal", text="1. Send Shredding OTP")
                self.shred_verify_otp_btn.configure(state="disabled")
                self.shred_otp_entry.configure(state="disabled")
                self.shred_otp_entry.delete(0, "end")
                self.shred_status_label_auth.configure(text="Request OTP to authorize shredding.", text_color="white")
                
            except Exception as e:
                self.db_manager.log_activity(f"FAILURE: Secure shredding failed for {filepath}. Error: {e}")
                messagebox.showerror("Error", f"Secure shredding failed. See log for details.")
            finally:
                self.update_log_display()

if __name__ == "__main__":
    app = SecureVaultApp()
    app.mainloop()