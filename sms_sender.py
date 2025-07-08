import requests

TEXTBEE_API_KEY = "your_textbee_api_key_here"  # Replace with your actual Textbee API key
DEVICE_ID = "your_device_id_here"  # Replace with your actual device ID     
BASE_URL = "https://api.textbee.dev/api/v1"

def send_otp_sms(phone_number, otp):
    message = f"Your OTP (PIN-derived key): {otp}"
    url = f"{BASE_URL}/gateway/devices/{DEVICE_ID}/send-sms"
    headers = {
        "x-api-key": TEXTBEE_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "recipients": [phone_number],
        "message": message
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        print("Textbee Raw Response:", response.status_code, response.text)

        if response.status_code in [200, 201, 202]:
            return True
        else:
            # Pop error dialog so you see what failed
            from tkinter import messagebox
            messagebox.showerror("Textbee API Error", f"Status: {response.status_code}\n{response.text}")
            return False

    except Exception as e:
        print("Error sending SMS:", e)
        from tkinter import messagebox
        messagebox.showerror("SMS Exception", str(e))
        return False