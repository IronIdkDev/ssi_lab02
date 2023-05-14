import time
import cryptography
import requests
import logging
import secrets
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag

logging.basicConfig(level=logging.ERROR)

# Function to establish connection and retrieve Bob's public key
def get_bob_public_key():
    max_retries = 3
    retries = 0

    while retries < max_retries:
        try:
            response = requests.get('http://localhost:8000/get_certificate', timeout=5)
            response.raise_for_status()
            return serialization.load_pem_public_key(response.content, backend=default_backend())
        except requests.exceptions.Timeout:
            logging.error("Connection timed out. Retrying...")
            time.sleep(1)
        except requests.exceptions.ConnectionError:
            logging.error("Connection error. Retrying...")
            time.sleep(1)
        except requests.exceptions.RequestException:
            logging.error("Connection failed:")
            logging.error("Retrying...")
            time.sleep(1)

        retries += 1

    logging.error("Failed to establish a connection with Bob's public key.")

# Function to encrypt the secret key using Bob's public key
def encrypt_secret_key(secret_key, public_key):
    random_key = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = kdf.derive(random_key)
    return public_key.encrypt(secret_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)), key

# Function to decrypt the message using the secret key
def decrypt_message(encrypted_message, key):
    if len(encrypted_message) < 28:
        raise ValueError("Invalid encrypted message")
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
    try:
        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_message
    except InvalidTag:
        raise InvalidTag("Authentication failed: Invalid tag")


# Step 1: Alice gets Bob's public key
bob_public_key = get_bob_public_key()

# Step 3: Alice encrypts the Secret Key using Bob's public key
secret_key = b'This is a secret key'
encrypted_secret_key, key = encrypt_secret_key(secret_key, bob_public_key)

# Step 4: Alice sends the encrypted Secret Key to Bob
try:
    response = requests.post('http://localhost:8000/receive_secret_key', data=encrypted_secret_key)
except requests.exceptions.ConnectionError as e:
    print("Connection error occurred:", e)
    exit(1)

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
    renewed_encrypted_message_2 = response.content
except requests.RequestException as e:
    print("Failed to retrieve renewed message:", e)
    exit(1)
