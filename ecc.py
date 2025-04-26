from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
import os
import base64
import json

def read_from_file(filename):
    with open(filename, 'r') as f:
        return str(f.read()) 

def generate_ec_key_pair(curve=ec.SECP256R1()):
    
    # Generate a private/public key
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    
    return private_key, public_key


def hybrid_ec_encrypt(message, recipient_public_key):

    # Convert message to bytes if it's a string
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Generate an ephemeral EC key pair (sender's temporary key)
    ephemeral_private_key, ephemeral_public_key = generate_ec_key_pair()
    
    # Perform ECDH key exchange to get shared secret
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)
    
    # Derive an AES key from the shared secret using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=None,
        info=b'handshake data'
    ).derive(shared_secret)
    
    # Generate a random IV for AES-CBC
    iv = os.urandom(16)
    
    # Pad the message to a multiple of 16 bytes (AES block size)
    padder = lambda s: s + (16 - len(s) % 16) * bytes([16 - len(s) % 16])
    padded_message = padder(message)
    
    # Encrypt the message with AES
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    
    # Serialize the ephemeral public key
    ephemeral_public_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Create a package containing all necessary components
    encryption_package = {
        'encrypted_message': base64.b64encode(encrypted_message).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8'),
        'ephemeral_public_key': base64.b64encode(ephemeral_public_bytes).decode('utf-8')
    }
    
    return json.dumps(encryption_package)

def hybrid_ec_decrypt(encrypted_package, recipient_private_key):

    # Parse the encryption package
    package = json.loads(encrypted_package)
    encrypted_message = base64.b64decode(package['encrypted_message'])
    iv = base64.b64decode(package['iv'])
    ephemeral_public_bytes = base64.b64decode(package['ephemeral_public_key'])
    
    # Load the ephemeral public key
    ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_bytes)
    
    # Perform ECDH key exchange to get the same shared secret
    shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public_key)
    
    # Derive the same AES key from the shared secret using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=None,
        info=b'handshake data'
    ).derive(shared_secret)
    
    # Decrypt the message with AES
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    
    # Unpad the message
    unpadder = lambda s: s[:-s[-1]]
    message = unpadder(padded_message)
    
    return message

def main():
    
    # Generate EC key pair (these would be the recipient's long-term keys)
    print("Generating Elliptic Curve key pair...")
    private_key, public_key = generate_ec_key_pair()
    
    i = 0

    while i != 100:
        i = i + 1
        
        filename = "./ciphertexts/"+str(i)
    
        # Encrypt and decrypt the short message
        encrypted_package = hybrid_ec_encrypt(read_from_file(filename), public_key)
        print("Encrypting ciphertext: "+str(i))
    
        hybrid_ec_decrypt(encrypted_package, private_key)
        print("Decrypting ciphertext: "+str(i))
    

if __name__ == "__main__":
    main()