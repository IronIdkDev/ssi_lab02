import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Server details
SERVER_HOST = 'localhost'
SERVER_PORT = 1234
ENCRYPTION_ALGORITHIM = ''

# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Connect to the server
    client_socket.connect((SERVER_HOST, SERVER_PORT))
    print('Connected to the server.')
    
    # Send GET_CERTIFICATE message to request a certificate
    client_socket.sendall('GET_CERTIFICATE'.encode())
    print('#Step 1: Sent GET_CERTIFICATE request.')

    # Receive the SENT_CERTIFICATE message from the server
    message = client_socket.recv(1024).decode()
    print('#Step 2 (Alice part): Received SENT_CERTIFICATE:', message)

    # Receive the certificate from the server
    certificate = client_socket.recv(1024)
    print('#Step 3 (Alice part): Received certificate (encrypted): ')
    print(certificate.decode() + '\n')

    # Generate a secret key
    secret_key = b'ThisIsASecretKey'
    print('#Step 4: Generated secret key successfully', '\n')

    # Read the certificate from the file
    with open('selfsigned_cert.pem', 'rb') as file:
        certificate_data = file.read()

    # Assume 'certificate_data' contains the raw certificate data
    certificate_pk = x509.load_pem_x509_certificate(certificate_data, default_backend())

    # Load the certificate's public key
    public_key = certificate_pk.public_key()

    # Encrypt the secret key using the certificate's public key
    encrypted_key = public_key.encrypt(
        secret_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print('#Step 5: Encrypted secret key successfully', '\n')

    # Send a message indicating we will send the parameters and the encrypted key
    client_socket.sendall('SECRET_KEY'.encode())
    print('#Step 6: Sent SECRET_KEY message to the server', '\n')
    
    # Send PARAMS message to send the details of the algorithms used to protect the messages. It may incude information about the encryption algorithm, the hashing algorithm, the padding algorithm, etc.
    PARAMS = ENCRYPTION_ALGORITHIM
    client_socket.sendall(PARAMS.encode())
    print('#Step 7: Sent PARAMS message to the server', '\n')

    # Send the encrypted key to the server
    client_socket.sendall(encrypted_key)
    print('#Step 8: Sent encrypted secret key to the server', '\n')

    while True:
        # Send data to the server
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
