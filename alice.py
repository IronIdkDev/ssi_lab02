import os
import requests
import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Step 1: Alice gets Bob's public key
response = requests.get('http://localhost:8000/get_certificate')
bob_public_key = serialization.load_pem_public_key(response.content, backend=default_backend())

# Step 3: Alice encrypts the Secret Key using Bob's public key
secret_key = b'This is a secret key'

# Generate a random key instead of using a hardcoded value
random_key = os.urandom(32)

# Generate a random salt instead of using a hardcoded value
salt = os.urandom(16)

# Use PBKDF2 to derive a key from the random key
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(random_key)

encrypted_secret_key = bob_public_key.encrypt(
    secret_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Step 4: Alice sends the encrypted Secret Key to Bob
response = requests.post('http://localhost:8000/receive_secret_key', data=encrypted_secret_key)

# Step 5: Alice receives the encrypted message from Bob
encrypted_message = response.content

# Step 6: Alice decrypts the message using the Secret Key
iv = os.urandom(12)  # Generate a random 96-bit IV
cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
decryptor = cipher.decryptor()
decryptor.authenticate_additional_data(b'')  # No additional authenticated data

# Split the encrypted message into the ciphertext and the authentication tag
ciphertext = encrypted_message[:-16]
tag = encrypted_message[-16:]

# Update the decryptor with the ciphertext
decrypted_message = decryptor.update(ciphertext)

# Pass the authentication tag during finalization
decrypted_message += decryptor.finalize_with_tag(tag)

# Step 7: Alice prints the decrypted message
print(f"Decrypted message: {decrypted_message.decode()}")

# Step 12: Alice renews the Secret Key
renewed_secret_key = b'This is a renewed secret key'

# Generate a new random key for renewal
renewed_random_key = os.urandom(32)

# Use PBKDF2 to derive a key from the new random key
renewed_key = kdf.derive(renewed_random_key)

renewed_encrypted_secret_key = bob_public_key.encrypt(
    renewed_secret_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Step 13: Alice sends the renewed Secret Key to Bob
response = requests.post('http://localhost:8000/renew_secret_key', data=renewed_encrypted_secret_key)

# Step 14: Alice receives the renewed encrypted message from Bob
renewed_encrypted_message = response.content

# Step 15: Alice decrypts the renewed message using the renewed Secret Key
renewed_iv = os.urandom(12)  # Generate a random 96-bit IV
renewed_cipher = Cipher(algorithms.AES(renewed_key), modes.GCM(renewed_iv), backend=default_backend())
renewed_decryptor = renewed_cipher.decryptor()
renewed_decryptor.authenticate_additional_data(b'')  # No additional authenticated data

# Split the renewed encrypted message into the ciphertext and the authentication tag
renewed_ciphertext = renewed_encrypted_message[:-16]
renewed_tag = renewed_encrypted_message[-16:]

# Update the renewed decryptor with the ciphertext
decrypted_renewed_message = renewed_decryptor.update(renewed_ciphertext)

# Pass the authentication tag during finalization
decrypted_renewed_message += renewed_decryptor.finalize_with_tag(renewed_tag)

# Step 16: Alice prints the decrypted renewed message
print(f"Decrypted renewed message: {decrypted_renewed_message.decode()}")
