import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1

import base64
import os
from cryptography.fernet import Fernet

# Server details
SERVER_HOST = 'localhost'
SERVER_PORT = 1234

SECRET_KEY_MESSAGE = 'SECRET_KEY'
GET_CERTIFICATE = 'GET_CERTIFICATE'
SENT_CERTIFICATE = 'SENT_CERTIFICATE'
RENEW_SECRET_KEY_MESSAGE = 'RENEW_SECRET_KEY'

def decrypt_with_sk(ciphertext, secret_key):
    backend = default_backend()

    # Create a cipher object with AES algorithm and CBC mode
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(b'\x00' * 16), backend=backend)

    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding from the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_message = unpadder.update(decrypted_data) + unpadder.finalize()

    return decrypted_message


# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Connect to the server
    client_socket.connect((SERVER_HOST, SERVER_PORT))
    print('Connected to the server.')

    # Send GET_CERTIFICATE message to request a certificate
    client_socket.sendall(GET_CERTIFICATE.encode())
    print('#Step 1: Sent GET_CERTIFICATE request.')

    while True:
        # Receive data from the server
        data = client_socket.recv(1024).decode()

        if not data:
            break

        print('Received:', data)

        if data.lower() == 'quit' or data.lower() == 'exit':
            print('Restarting the server...')
            break

        if data == SENT_CERTIFICATE:
            # Read from bob.csr
            with open("bob.csr", "rb") as f:
                csr = f.read()

            x509_csr = x509.load_pem_x509_csr(csr)
            if x509_csr.is_signature_valid:
                print("CSR signature is valid!!!")
            else:
                print("CSR signature is invalid!!!")

            # Get the public key from bob.csr
            public_key = x509_csr.public_key()

            # Generate a secret key
            secret_key = b'ThisIsASecretKey'
            print('#Step 4: Generated secret key successfully', '\n')

            # Encrypt the secret key using the certificate's public key
            encrypted_key = public_key.encrypt(
                secret_key,
                OAEP(
                    mgf=MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print('#Step 5: Encrypted secret key successfully', '\n')

            # Send a message indicating we will send the parameters and the encrypted key
            client_socket.send(SECRET_KEY_MESSAGE.encode())
            print('#Step 6: Sent SECRET_KEY message to the server', '\n')

            # Send PARAMS message to send the details of the algorithms used to protect the messages.
            # It may include information about the encryption algorithm, the hashing algorithm, the padding algorithm, etc.
            PARAMS = 'ENCRYPTION_ALGORITHM_DETAILS'
            client_socket.send(PARAMS.encode())
            print('#Step 7: Sent PARAMS message to the server', '\n')

            # Convert the encrypted_key to bytes
            encrypted_key_bytes = encrypted_key

            # Send the length of the encrypted_key_bytes as a 4-byte integer
            encrypted_key_length = len(encrypted_key_bytes)
            client_socket.send(encrypted_key_length.to_bytes(4, byteorder='big'))

            # Send the encrypted_key_bytes
            client_socket.send(encrypted_key_bytes)

            # Send the encrypted key to the server
            client_socket.sendall(encrypted_key_bytes)
            print('#Step 8: Sent encrypted secret key to the server', '\n')

            # Receive the encrypted message from the server
            encrypted_message = client_socket.recv(1024)
            print('#Step 11: Received encrypted message from the server', '\n')

            decrypted_message = decrypt_with_sk(encrypted_message, secret_key)
            print('#Step 12: Decrypted message from the server:', decrypted_message.decode(), '\n')

    while True:
        secret_key = b'NEWSecretKey'

        encrypted_key = public_key.encrypt(
            secret_key,
            OAEP(
                mgf=MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print('#Step 13: Encrypted secret key successfully', '\n')

        # Send a message indicating we will send the parameters and the encrypted key
        client_socket.sendall(RENEW_SECRET_KEY_MESSAGE.encode())
        print('#Step 14: Sent RENEW_SECRET_KEY message to the server', '\n')

        message = input('Enter a message (or "quit" to exit): ')
        client_socket.sendall(message.encode())

        if message.lower() == 'quit':
            break

        # Receive data from the server
        response = client_socket.recv(1024).decode()
        print('Received:', response)

except ConnectionRefusedError:
    print('Connection refused. Make sure the server is running.')

finally:
    # Close the socket
    client_socket.close()
    print('Disconnected from the server.')
