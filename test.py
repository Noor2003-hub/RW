
from cs50 import SQL
from cryptography.fernet import Fernet
import base64
import os
ENCRYPTION_KEY = 'EE_TQZC1dolC7MvOufqONuIBscclbe8FuKJTQ6hcGPw='

# Use the hardcoded key directly
cipher_suite = Fernet(ENCRYPTION_KEY)

# Encrypt data

def encrypt_message(data):
    encrypted_data = cipher_suite.encrypt(data.encode())
    # Convert encrypted bytes to base64-encoded string for storage
    return base64.urlsafe_b64encode(encrypted_data).decode()

def decrypt_message(encrypted_data):
    # Convert base64-encoded string back to encrypted bytes
    encrypted_data = base64.urlsafe_b64decode(encrypted_data.encode())
    return cipher_suite.decrypt(encrypted_data).decode()
db = SQL("sqlite:///project.db")
m=encrypt_message('hi')
#db.execute('update messages set content=? where id=?',m,54)
print(decrypt_message(db.execute('select content from messages where id=?',54)[0]['content']))