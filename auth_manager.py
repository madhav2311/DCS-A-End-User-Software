"""
Manages OTP generation, real SMTP communication, and security alerts.
Loads SMTP credentials dynamically from the database.
"""
import smtplib
import ssl
import time
import random
from email.message import EmailMessage
from config import Config

class AuthManager:
    """Manages OTP generation and verification (REAL SMTP ATTEMPT)."""

    def __init__(self, db_manager):
        self.db = db_manager
        self._current_otp = None
        self._otp_expiration = 0

    def generate_otp(self):
        """Generates a 6-digit OTP and sets an expiration time (e.g., 5 minutes)."""
        otp = str(random.randint(100000, 999999))
        self._current_otp = otp
        self._otp_expiration = time.time() + 300 # 5 minutes validity
        return otp

    def _send_email(self, recipient_email, subject, body):
        """
        Base function to attempt sending an email via SMTP.
        Dynamically loads SMTP credentials from the database.
        """
        smtp_settings = self.db.get_smtp_settings()
        sender_email = smtp_settings.get('email')
        password = smtp_settings.get('password')
        
        if not sender_email or not password:
            return "ERROR (Config): Sender Email or App Password not configured in the database. Please re-register."

        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg.set_content(body)

        context = ssl.create_default_context()
        
        try:
            with smtplib.SMTP_SSL(Config.SMTP_HOST, Config.SMTP_PORT, context=context) as server:
                server.login(sender_email, password)
                server.send_message(msg)
            return "SUCCESS: Real SMTP email sent."
        
        except smtplib.SMTPAuthenticationError:
            return "ERROR (Auth): Failed to log in to SMTP server. Check App Password and sender email."
        except smtplib.SMTPConnectError:
            return "ERROR (Connection): Could not connect to SMTP server. Check host/port or firewall/sandbox rules."
        except Exception as e:
            return f"ERROR (General): Failed to send email via SMTP. Details: {e}"

    def send_failed_login_alert(self, attempted_email):
        """Sends a security alert email to the registered user."""
        registered_email = self.db.get_user_email()
        
        if not registered_email:
            self.db.log_activity("ALERT_FAIL: Cannot send alert, no registered user found.")
            return

        subject = f"🚨 URGENT: Failed Login Attempt to {Config.APP_NAME} 🚨"
        body = f"""
        Dear {registered_email},

        This is an automatic security alert from your {Config.APP_NAME}.

        A failed login attempt occurred at: {time.strftime('%Y-%m-%d %H:%M:%S')}

        The attempt was made using the registered email: {attempted_email}

        Reason: Incorrect Master Password.

        If this was not you, please secure your system immediately.

        ---
        This email was sent by the DCS Security Vault application.
        """
        smtp_result = self._send_email(registered_email, subject, body)
        
        if smtp_result.startswith("SUCCESS"):
            self.db.log_activity(f"ALERT_SENT: Failed login alert sent to {registered_email}.")
        else:
            self.db.log_activity(f"ALERT_FAIL: Could not send alert via SMTP. Reason: {smtp_result}")


    def send_otp_code(self, email):
        """
        Generates OTP and attempts to send via REAL SMTP.
        """
        otp = self.generate_otp()
        
        subject = f"[{Config.APP_NAME}] One-Time Password (OTP)"
        body = f"""
        Dear {email},

        Your One-Time Password (OTP) for {Config.APP_NAME} is: {otp}

        This code is valid for 5 minutes. Do not share this code with anyone.

        This email was sent by the DCS Security Vault application.
        """

        # 1. Attempt Real SMTP Send
        smtp_result = self._send_email(email, subject, body)
        
        if smtp_result.startswith("SUCCESS"):
            log_msg = f"REAL SMTP: OTP email sent to {email}. Result: {smtp_result}"
            self.db.log_activity(log_msg)
            return {'status': 'success', 'message': "OTP successfully sent via SMTP."}
        
        # 2. Fallback to Simulation if Real SMTP Failed
        
        # Added detailed console output for debugging and fallback access
        print("\n" + "="*70)
        print(f"*** DCS SECURE VAULT OTP FALLBACK REQUIRED ***")
        print(f"REAL SMTP FAILURE REASON: {smtp_result}")
        print(f"ACTION REQUIRED: Enter the code below.")
        print(f"OTP for {email} (Valid for 5 minutes): {otp}")
        print("Note: This code is logged in the UI's Activity Log and console.")
        print("="*70 + "\n")

        log_msg = f"FALLBACK SIMULATION: OTP sent to {email}. OTP Code is: {otp}. SMTP Status: {smtp_result}"
        self.db.log_activity(log_msg)
        return {'status': 'success', 'message': f"OTP printed to console/log. SMTP Status: {smtp_result}"}

    def verify_otp_code(self, user_input_otp):
        """
        Verifies the user's OTP input.
        """
        email = self.db.get_user_email()
        if self._current_otp is None:
            return {'status': False, 'email': email, 'message': "No OTP generated. Request new one."}
        if time.time() > self._otp_expiration:
            self._current_otp = None
            return {'status': False, 'email': email, 'message': "OTP has expired."}
        if user_input_otp != self._current_otp:
            return {'status': False, 'email': email, 'message': "Invalid OTP."}
        
        # OTP success
        self._current_otp = None # Invalidate after use
        return {'status': True, 'email': email, 'message': "OTP verified."}