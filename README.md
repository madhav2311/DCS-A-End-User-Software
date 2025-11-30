DCS Security System (Secure Vault Edition)

Project Goal

To build a professional, standalone desktop application designed to ensure the confidentiality of sensitive files through strong encryption and guarantee irrecoverability through permanent data destruction, enforced by two-factor authentication.

The application utilizes a modular Python architecture, a local SQLite database for persistence, and robust cryptographic primitives.

Features

🔐 Authentication and Access Control

One-Time Registration: Mandatory initial setup to register the Master User and configure the dynamic SMTP sender credentials.

Two-Factor Authentication (2FA): Primary login requires Master Password verification followed by a One-Time Password (OTP) sent via email (SMTP).

Strict Security Gate: All cryptographic operations (Encrypt, Decrypt, Shred) are disabled and inaccessible until successful 2FA login.

Failed Login Alert: The registered user receives an immediate email alert notification if a login attempt fails due to an incorrect password.

🛡️ Security and File Operations

Strong Encryption: Uses the Fernet library (based on AES-128 in CBC mode) with a key derived from the Master Password using PBKDF2HMAC (480,000 iterations).

Secure Vault Container: Encrypted files are saved to the dedicated SECURE_VAULT directory with the .dcsenc extension.

Mandatory Data Shredding:

On Encryption: The original plaintext file is immediately destroyed using a secure shredding algorithm.

On Decryption: The encrypted .dcsenc vault container is immediately destroyed after decryption.

3-Pass Secure Shredding: Files destined for destruction are overwritten three times (random data, then two passes of zeros) before deletion, ensuring irrecoverability.

Shredding 2FA: The final "DESTROY FILE SECURELY" action requires a separate, mandatory OTP verification initiated directly on the Shred screen.

📊 Utilities and Persistence

Activity Logging: All key events (Login, Crypto Ops, Shredding) are permanently recorded in the local SQLite database.

Log Management: UI utilities to view, clear, and save the activity log to a .txt file.

OS Viewer Integration: Buttons to open source files or the SECURE_VAULT directory using the operating system's default file viewer.

🛠️ Prerequisites

This application requires Python 3.8+ and the following dependencies.

Installation

Clone the Repository:

git clone https://your-repository-link/dcs-security-vault.git
cd dcs-security-vault


Install Dependencies:
Use the provided requirements.txt to install the external libraries:

pip install -r requirements.txt


(Dependencies: customtkinter, cryptography)

🚀 Usage and Configuration

1. Running the Application

python main.py


2. One-Time Master Registration & SMTP Setup

On the first launch, the application will detect an empty database and prompt you for the ONE-TIME MASTER REGISTRATION & SMTP SETUP.

Crucial Step for Email Delivery: For the 2FA and security alerts to function, you must provide valid SMTP credentials. If using services like Gmail, you MUST generate and use a specific App Password for the Sender App Password field. Do not use your main account password.

Field

Description

Master Email

Your primary email (receives OTPs and security alerts).

Master Password

Your secure password for accessing the vault.

Sender Email

The email address used to send the OTPs (must be configured for external SMTP access).

Sender App Password

The unique token/App Password generated from your email provider's security settings.

These sender credentials are encrypted and stored securely in the local database, replacing any hardcoded values.

3. Login Flow

Verify Credentials: Enter your Master Password and click "Verify Credentials & Get OTP."

OTP Delivery: Check your Master Email inbox (or the console/Activity Log if running in a restricted environment) for the 6-digit code.

Verify OTP: Enter the code and click "Verify OTP & Log In" to gain access to the Vault.

4. File Operations

Navigate to the "Cryptographic Operations" or "Secure Data Destruction" tab to use the security features. Remember that shredding on the dedicated tab requires a second, immediate OTP verification for maximum security before the final "DESTROY" button is enabled.
