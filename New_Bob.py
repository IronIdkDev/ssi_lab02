import socket
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

# Server details
SERVER_HOST = 'localhost'
SERVER_PORT = 1234
SECRET_KEY_MESSAGE = 'SECRET_KEY'

GET_CERTIFICATE = 'GET_CERTIFICATE'
SENT_CERTIFICATE = 'SENT_CERTIFICATE'
RENEW_SECRET_KEY_MESSAGE = 'RENEW_SECRET_KEY'


#Creates a self Signed Certicifate
def create_self_signed_certificate(key):
    print('Creating a self-signed certificate...')
    print('To do this we need to collect some data. Please enter enter it below:')
    country_name = 'PT' #input('Country Name (2 letter code): ')
    state_or_province_name = 'PT' #input('State or Province Name (full name): ')
    locality_name = 'PT' #input('Locality Name (eg, city): ')
    organization_name = 'PT' #input('Organization Name (eg, company): ')
    common_name = 'PT' #input('Common Name (e.g. server FQDN or YOUR name): ')
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=True, crl_sign=True, content_commitment=False, data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False),
        critical=True
    # Sign our certificate with our private key
    ).sign(key, hashes.SHA256())
    # Write our certificate out to disk.
    with open("selfsigned_cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        print('Certificate created successfully.')


    #CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Details to be contained in the certificate
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])).add_extension(
        x509.SubjectAlternativeName([
            # Alternative names for common name
            x509.DNSName(u"mysite.com"),
            x509.DNSName(u"www.mysite.com"),
        ]),
        critical=False,
    # Sign the CSR with our private key
    ).sign(key, hashes.SHA256())

    # write the CSR to disk
    with open("bob.csr", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
        
def create_key_pair(filename):
    print('Creating a key pair...')
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Write our key to disk for safe keeping
    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b'bobP4ssword'),
        ))
        print('Key pair created successfully.')

def read_key_pair(filename):
    password = (b'bobP4ssword')
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password,
        )
    print('Key pair read successfully.')
    return private_key
    
def send_certificate_to_client(client_socket):
    client_socket.sendall(SENT_CERTIFICATE.encode())
    print('Sent message: #Step 2: Sending the certificate.')
    
    #with open("selfsigned_cert.pem", "rb") as f:
    #    certificate = f.read()
    #client_socket.sendall(certificate)
    print('Sent certificate to the client.')

#def decrypt_secret_key(encrypted_key, params):
#    print('\n', 'Decrypting the secret key...')
#    # Decrypt the secret key
#    decrypt_secret_key = rsa.decrypt(encrypted_key, params)
#    return decrypt_secret_key

def decipher_with_private_key(privkey, ciphertext, params):
    print("\nDeciphering with the private key...")
    plaintext = privkey.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    print("Plaintext = " + str(plaintext.decode()))

# Encrypt with AES, using multiple modes
def do_aes(message, mode, key, iv=None, nonce=None):
    print("\nEncrypting with AES, 256-bit key, mode " + mode)

    print("Data:" + str(message))

    # AES works on blocks of 128bits (32 bytes) so we need to make user the message is multiple of the block lenght
    if len(message) % 16 != 0:
        # handling the padding of the messages
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        paddeddata = padder.update(message)
        paddeddata += padder.finalize()
        print("Data (padded):" +  str(paddeddata))
        message = paddeddata

    print("KEY = " + str(base64.b64encode(key)))
    if mode == 'ECB':
        cipher = Cipher(algorithms.AES(key), modes.ECB())
    if mode == 'CBC':
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    if mode == 'OFB':
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
    if mode == 'CFB':
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    if mode == 'CTR':
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    print("Ciphertext = " + str(base64.b64encode(ciphertext)))

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(plaintext)
    plaintext_data = data + unpadder.finalize()

    print("Plaintext = " + str(plaintext_data.decode('utf-8')))


def start_server():
    server_running = True
    create_key_pair('bob_key.pem')
    privkey = read_key_pair('bob_key.pem')
    create_self_signed_certificate(privkey)
    while server_running == True:
        try:
            # Create a socket object
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Bind the server to the specified address and port
            server_socket.bind((SERVER_HOST, SERVER_PORT))

            # Listen for incoming connections
            server_socket.listen()

            print('Waiting for incoming connections...')

            # Accept a client connection
            client_socket, client_address = server_socket.accept()
            print('Connected to:', client_address)

            while True:
                # Receive data from the client
                data = client_socket.recv(1024).decode()

                if not data:
                    break

                print('Received:', data)

                if data.lower() == 'quit' or data.lower() == 'exit':
                    print('Restarting the server...')
                    break

                if data == GET_CERTIFICATE:
                    # Send the certificate to the client
                    send_certificate_to_client(client_socket)
                    print('#Step 2: Certificate sent to the client successfully.')
                    continue

                if data == SECRET_KEY_MESSAGE or data == RENEW_SECRET_KEY_MESSAGE:
                    # Prepare to receive PARAMS and encrypted secret key
                    params = client_socket.recv(1024)
                    print('Received PARAMS:', params)
                    
                    encrypted_key = client_socket.recv(1024)
                    print('Received encrypted secret key:', encrypted_key)

                    # Decrypt the secret key
                    decrypted_secret_key = decipher_with_private_key(privkey, encrypted_key, params)
                    print('#Step 9: Decrypted secret key:', decrypted_secret_key)

                    # Send a response to the client
                    response = 'Encryption completed.'

                    #if params.toLower() == "aes":    
                    #iv = os.urandom(16)
                    #nonce = os.urandom(16)
                    #do_aes(response, 'ECB', decrypted_secret_key, iv, nonce)
                    #do_aes(response, 'CBC', decrypted_secret_key, iv, nonce)
                    #do_aes(response, 'OFB', decrypted_secret_key, iv, nonce)
                    #do_aes(response, 'CFB', decrypted_secret_key, iv, nonce)
                    #do_aes(response, 'CTR', decrypted_secret_key, iv, nonce)
                    print("#Step 10: mensage encrypted with SK")

                    client_socket.sendall(response.encode())
                    continue


                # Send a response to the client
                #response = 'Message received: ' + data
                #client_socket.sendall(response.encode())

            # Close the client connection
            client_socket.close()
            print('Disconnected from:', client_address)

            server_socket.close()

            if data.lower() == 'quit' or data.lower() == 'exit':
                continue
        except KeyboardInterrupt:
            print('Shutting down the server...')
            server_running = False  

# Start the server
start_server()