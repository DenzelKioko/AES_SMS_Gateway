from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import base64

BLOCK_SIZE = 16

def pad(text):
    padding_len = BLOCK_SIZE - len(text) % BLOCK_SIZE
    return text + chr(padding_len) * padding_len

def unpad(text):
    padding_len = ord(text[-1])
    return text[:-padding_len]

def generate_key_from_pin(pin: str):
    # Use a consistent salt for demo (can also derive per user)
    salt = b'static_demo_salt'
    return PBKDF2(pin, salt, dkLen=16, count=100000, hmac_hash_module=SHA256)

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(message)
    encrypted = cipher.encrypt(padded.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_message(encrypted_message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decoded = base64.b64decode(encrypted_message)
    decrypted = cipher.decrypt(decoded).decode()
    return unpad(decrypted)
