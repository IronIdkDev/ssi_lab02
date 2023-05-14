import os
import time
import cryptography
import requests
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Function to establish connection and retrieve Bob's public key
def get_bob_public_key():
    while True:
        try:
            response = requests.get('http://localhost:8000/get_certificate', timeout=5)
            response.raise_for_status()
            return serialization.load_pem_public_key(response.content, backend=default_backend())
        except requests.RequestException:
            print("Connection failed. Retrying...")
            time.sleep(1)

# Function to encrypt the secret key using Bob's public key
def encrypt_secret_key(secret_key, public_key):
    random_key = os.urandom(32)
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = kdf.derive(random_key)
    return public_key.encrypt(secret_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)), key

# Function to decrypt the message using the secret key
def decrypt_message(encrypted_message, key):
    iv, ciphertext, tag = encrypted_message[:12], encrypted_message[12:-16], encrypted_message[-16:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(b'')
    decrypted_message = decryptor.update(ciphertext)
    try:
        decrypted_message += decryptor.finalize_with_tag(tag)
        return decrypted_message.decode()
    except cryptography.exceptions.InvalidTag:
        return None

# Step 1: Alice gets Bob's public key
bob_public_key = get_bob_public_key()

# Step 3: Alice encrypts the Secret Key using Bob's public key
secret_key = b'This is a secret key'
encrypted_secret_key, key = encrypt_secret_key(secret_key, bob_public_key)

# Step 4: Alice sends the encrypted Secret Key to Bob
response = requests.post('http://localhost:8000/receive_secret_key', data=encrypted_secret_key)

# Step 5: Alice receives the encrypted message from Bob
encrypted_message = response.content

# Step 6: Alice decrypts the message using the Secret Key
decrypted_message = decrypt_message(encrypted_message, key)
if decrypted_message:
    print(f"Decrypted message: {decrypted_message}")
else:
    print("Authentication failed: Invalid tag")

# Step 12: Alice renews the Secret Key
renewed_secret_key = b'This is a renewed secret key'
renewed_encrypted_secret_key, renewed_key = encrypt_secret_key(renewed_secret_key, bob_public_key)

# Step 13: Alice sends the renewed Secret Key to Bob
response = requests.post('http://localhost:8000/renew_secret_key', data=renewed_encrypted_secret_key)

# Step 14: Alice receives the renewed encrypted message from Bob
renewed_encrypted_message = response.content

# Step 15: Alice decrypts the renewed message using the renewed Secret Key
renewed_iv, renewed_ciphertext, renewed_tag = renewed_encrypted_message[:12], renewed_encrypted_message[12:-16], renewed_encrypted_message[-16:]
renewed_cipher = Cipher(algorithms.AES(renewed_key), modes.GCM(renewed_iv), backend=default_backend())
renewed_decryptor = renewed_cipher.decryptor()
renewed_decryptor.authenticate_additional_data(b'')
decrypted_renewed_message = renewed_decryptor.update(renewed_ciphertext)
try:
    decrypted_renewed_message += renewed_decryptor.finalize_with_tag(renewed_tag)
    print(f"Decrypted renewed message: {decrypted_renewed_message.decode()}")
except cryptography.exceptions.InvalidTag:
    print("Authentication failed: Invalid renewed tag")

# Step 16: Alice prints the decrypted renewed message
print(f"Decrypted renewed message: {decrypted_renewed_message}")