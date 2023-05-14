from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import requests

# Step 1: Alice sends a GET_CERTIFICATE to Bob
response = requests.get('http://localhost:8000/get_certificate')
certificate = response.content

# Step 4: Alice creates a secret SK key
secret_key = b'ThisIsASecretKey'

# Step 5: Alice encrypts her SK with Bob's public key
public_key = serialization.load_pem_public_key(certificate, backend=default_backend())
cipher = public_key.encrypt(
    secret_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Step 6: Alice sends the SECRET_KEY to Bob
requests.post('http://localhost:8000/receive_secret_key', data=cipher)

# Step 13: Alice creates a second Secret Key
new_secret_key = b'ThisIsANewSecretKey'

# Step 15: Alice encrypts the new Secret Key with Bob's public key
new_cipher = public_key.encrypt(
    new_secret_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Step 16: Alice sends the renew Secret Key
requests.post('http://localhost:8000/renew_secret_key', data=new_cipher)

# Step 20: Alice deciphers the message using the renewed secret key
decipher = Cipher(algorithms.AES(new_secret_key), modes.ECB(), backend=default_backend()).decryptor()
plaintext = decipher.update(ciphertext) + decipher.finalize()
print("Decrypted message:", plaintext.decode())
