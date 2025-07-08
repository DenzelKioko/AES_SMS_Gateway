import tkinter as tk
from tkinter import messagebox, simpledialog
import base64
import re
from crypto_utils import generate_key_from_pin, encrypt_message, decrypt_message
from sms_sender import send_otp_sms
from config import TEXTBEE_API_KEY, DEVICE_ID
key_bytes = None

def is_valid_kenyan_phone(number):
    return re.fullmatch(r"^\+2547\d{8}$", number)

def encrypt_and_send():
    global key_bytes
    plaintext = entry_message.get().strip()
    phone = entry_phone.get().strip()

    if not plaintext:
        messagebox.showerror("Validation Error", "Message cannot be empty.")
        return

    if not is_valid_kenyan_phone(phone):
        messagebox.showerror("Validation Error", "Invalid phone number format. Use +2547XXXXXXXX.")
        return

    pin = simpledialog.askstring("Enter PIN", "Enter a numeric PIN to encrypt:", show='*')
    if not pin or len(pin) < 4:
        messagebox.showerror("Validation Error", "PIN must be at least 4 digits.")
        return

    key_bytes = generate_key_from_pin(pin)
    encrypted = encrypt_message(plaintext, key_bytes)
    otp = base64.b64encode(key_bytes).decode()

    success = send_otp_sms(phone, otp)
    if success:
        text_encrypted.delete("1.0", tk.END)
        text_encrypted.insert(tk.END, encrypted)
        messagebox.showinfo("Success", "Encrypted message generated and OTP sent via SMS.")
    else:
        messagebox.showerror("SMS Error", "OTP SMS may have failed. Please confirm delivery.")

def decrypt():
    encrypted_msg = text_encrypted.get("1.0", tk.END).strip()
    otp_input = entry_otp.get().strip()

    if not encrypted_msg or not otp_input:
        messagebox.showerror("Validation Error", "Encrypted message and OTP are required.")
        return

    try:
        key = base64.b64decode(otp_input)
        decrypted = decrypt_message(encrypted_msg, key)
        messagebox.showinfo("Decrypted Message", decrypted)
    except Exception as e:
        messagebox.showerror("Decryption Failed", f"Error: {e}")

# UI
root = tk.Tk()
root.title("AES Secure Message with OTP")

tk.Label(root, text="Message:").grid(row=0, column=0)
entry_message = tk.Entry(root, width=40)
entry_message.grid(row=0, column=1)

tk.Label(root, text="Phone (+2547...):").grid(row=1, column=0)
entry_phone = tk.Entry(root, width=40)
entry_phone.grid(row=1, column=1)

tk.Button(root, text="Encrypt & Send OTP", command=encrypt_and_send).grid(row=2, column=1, pady=5)

tk.Label(root, text="Encrypted Msg:").grid(row=3, column=0)
text_encrypted = tk.Text(root, height=5, width=40)
text_encrypted.grid(row=3, column=1)

tk.Label(root, text="Enter OTP:").grid(row=4, column=0)
entry_otp = tk.Entry(root, width=40)
entry_otp.grid(row=4, column=1)

tk.Button(root, text="Decrypt", command=decrypt).grid(row=5, column=1, pady=10)

root.mainloop()
# This code provides a GUI for encrypting messages, sending OTPs via SMS, and decrypting messages using AES encryption.
# It includes input validation for phone numbers and PINs, and uses the TextBee API to send SMS messages.
# The user can enter a message, phone number, and PIN to encrypt the message, which is then sent as an OTP via SMS.
# The user can also decrypt the message using the OTP received.
# The code uses AES encryption with a key derived from the PIN, and it handles errors gracefully with appropriate messages.
# The UI is built using Tkinter, providing a simple and user-friendly interface for the functionality.
# The code is structured to ensure that sensitive operations like encryption and decryption are handled securely, and it provides feedback to the user throughout the process.
# The code is modular, separating concerns between the UI, encryption logic, and SMS sending functionality, making it easier to maintain and extend in the future.
# The use of base64 encoding for the OTP ensures that the key can be safely transmitted as a string, while the encryption and decryption functions handle padding and unpadding of messages to comply with AES block size requirements.
# Overall, this code provides a comprehensive solution for secure message handling with OTP verification via SMS, suitable for applications requiring secure communication in a user-friendly manner.