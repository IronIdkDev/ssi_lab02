import socket
import base64
import datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

# Server details
SERVER_HOST = 'localhost'
SERVER_PORT = 1234
ENCRYPTION_ALGORITHIM = ''

# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def load_csr_and_issue_certificate(key, cert, csr):
    x509_ca_cert = x509.load_pem_x509_certificate(cert)

    x509_csr = x509.load_pem_x509_csr(csr)
    if x509_csr.is_signature_valid:
        print("CSR signature is valid!!!")
    else:
        print("CSR signature is invalid!!!")
        return False

    s_cn = x509_csr.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
    s_st = x509_csr.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value
    s_ln = x509_csr.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value
    s_on = x509_csr.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    s_c = x509_csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    s_publickey = x509_csr.public_key()

    i_cn = x509_ca_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
    i_st = x509_ca_cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value
    i_ln = x509_ca_cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value
    i_on = x509_ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    i_c = x509_ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    print("CSR information")
    print("Country Name: " + s_cn)
    print("State or Province Name: " + s_st)
    print("Locality Name: " + s_ln)
    print("Organization Name: " + s_on)
    print("Common Name: " + s_c)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, s_cn),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, s_st),
        x509.NameAttribute(NameOID.LOCALITY_NAME, s_ln),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, s_on),
        x509.NameAttribute(NameOID.COMMON_NAME, s_c),
    ])

    issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, i_cn),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, i_st),
        x509.NameAttribute(NameOID.LOCALITY_NAME, i_ln),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, i_on),
        x509.NameAttribute(NameOID.COMMON_NAME, i_c),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        s_publickey
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # 1 year in duration
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=False, crl_sign=False,
                      content_commitment=False, data_encipherment=True, key_agreement=True, encipher_only=False,
                      decipher_only=False),
        critical=True
        # Sign the certificate
    ).sign(key, hashes.SHA256())
    # write certificate to disk
    with open("user.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return True

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
    
    # Decrypt the certificate data
    decrypted_certificate = base64.b64decode(certificate)
    print('Decrypted certificate data: ', decrypted_certificate.decode() + '\n')

    # Generate a secret key
    secret_key = b'ThisIsASecretKey'
    print('#Step 4: Generated secret key successfully', '\n')

    # Assume 'decrypted_certificate' contains the raw decrypted certificate data
    certificate_pk = x509.load_pem_x509_certificate(decrypted_certificate, default_backend())

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
