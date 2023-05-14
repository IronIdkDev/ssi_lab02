from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from flask import Flask, request, escape
from flask_wtf.csrf import CSRFProtect
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
csrf = CSRFProtect(app)
csrf.init_app(app)

# Generate Bob's private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
)

# Route for the root path
@app.route('/')
def home():
    return "Server is running"

# Step 2: Bob replies with a SEND_CERTIFICATE to ALICE
@app.route('/get_certificate', methods=['GET'])
def get_certificate():
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

# Step 9: Bob deciphers the Secret Key using Bob's private Key
@app.route('/receive_secret_key', methods=['POST'])
def receive_secret_key():
    secret_key_cipher = request.data
    secret_key = private_key.decrypt(
        secret_key_cipher,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Step 10: Bob encrypts the message using its Secret Key
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(secret_key), modes.GCM(iv), backend=default_backend()).encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    message = b'This is a secret message'
    padded_message = padder.update(message) + padder.finalize()
    ciphertext = cipher.update(padded_message) + cipher.finalize()

    # Step 11: Bob sends the encrypted message with the Secret Key
    return escape(ciphertext)

# Step 17: Bob deciphers the renewed Secret Key with Bob's private key
@app.route('/renew_secret_key', methods=['POST'])
def renew_secret_key():
    renewed_secret_key_cipher = request.data
    renewed_secret_key = private_key.decrypt(
        renewed_secret_key_cipher,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Step 18: Bob encrypts the message with the new Secret Key
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(renewed_secret_key), modes.GCM(iv), backend=default_backend()).encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    message = b'This is a renewed secret message'
    padded_message = padder.update(message) + padder.finalize()
    ciphertext = cipher.update(padded_message) + cipher.finalize()

    # Step 19: Bob sends the message with the renewed secret key
    return escape(ciphertext)

if __name__ == '__main__':
    app.run(host='localhost', port=8000)