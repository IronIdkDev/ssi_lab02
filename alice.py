import os
import time
import cryptography
import requests
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag


# Function to establish connection and retrieve Bob's public key
def get_bob_public_key():
    while True:
        try:
            response = requests.get('http://localhost:8000/get_certificate', timeout=5)
            response.raise_for_status()
            return serialization.load_pem_public_key(response.content, backend=default_backend())
        except requests.exceptions.Timeout:
            print("Connection timed out. Retrying...")
            time.sleep(1)
        except requests.exceptions.ConnectionError:
            print("Connection error. Retrying...")
            time.sleep(1)
        except requests.exceptions.RequestException as e:
            print("Connection failed:", e)
            print("Retrying...")
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
    iv, ciphertext, tag = (
        encrypted_message[:12],
        encrypted_message[12:-16],
        encrypted_message[-16:]
    )
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(b'')
    decrypted_message = decryptor.update(ciphertext)
    try:
        decryptor.finalize()
    except cryptography.exceptions.InvalidTag as e:
        raise e
    return decrypted_message

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
    # Step 7: Alice prints the decrypted message
    print(f"Decrypted message: {decrypted_message}")
else:
    print("Authentication failed: Invalid tag")

# Step 12: Alice renews the Secret Key
renewed_secret_key = b'This is a renewed secret key'
renewed_encrypted_secret_key, renewed_key = encrypt_secret_key(renewed_secret_key, bob_public_key)

# Step 13: Alice sends the renewed Secret Key to Bob
try:
    response = requests.post('http://localhost:8000/renew_secret_key', data=renewed_encrypted_secret_key, timeout=5)
    response.raise_for_status()
except requests.RequestException as e:
    print("Renewal failed:", e)
    exit(1)

# Step 14: Alice receives the renewed encrypted message from Bob
renewed_encrypted_message = response.content

# Step 15: Alice receives the renewed encrypted message from Bob
try:
    response = requests.get('http://localhost:8000/get_renewed_message', timeout=5)
    response.raise_for_status()
    renewed_encrypted_message = response.content
except requests.RequestException as e:
    print("Failed to retrieve renewed message:", e)
    exit(1)