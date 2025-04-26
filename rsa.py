from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
import os
import base64
import json

def read_from_file(filename):
    
    # open and read the whole plaintext file
    with open(filename, 'r') as f:
        return str(f.read()) 

def generate_rsa_key_pair(key_size=2048):

    # generate private key with e = 65537 and defined bit length
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    # make a public key based on private key
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_keys(private_key, public_key):

    # make a serialized version of the private and public key
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key_pem, public_key_pem

def hybrid_encrypt(message, public_key):

    # Convert message to bytes if it's a string
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Generate a random AES key and IV
    aes_key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)
    
    # Pad the message to a multiple of 16 bytes (AES block size)
    padder = lambda s: s + (16 - len(s) % 16) * bytes([16 - len(s) % 16])
    padded_message = padder(message)
    
    # Encrypt the message with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    
    # Encrypt the AES key with RSA
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Create a package containing all necessary components
    encryption_package = {
        'encrypted_message': base64.b64encode(encrypted_message).decode('utf-8'),
        'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8')
    }
    
    return json.dumps(encryption_package)

def hybrid_decrypt(encrypted_package, private_key):

    # Parse the encryption package
    package = json.loads(encrypted_package)
    encrypted_message = base64.b64decode(package['encrypted_message'])
    encrypted_key = base64.b64decode(package['encrypted_key'])
    iv = base64.b64decode(package['iv'])
    
    # Decrypt the AES key with RSA
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Decrypt the message with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    
    # Unpad the message
    unpadder = lambda s: s[:-s[-1]]
    message = unpadder(padded_message)
    
    return message

def main():
    
    # Generate RSA key pair
    print("Generating RSA key pair...")
    private_key, public_key = generate_rsa_key_pair(2048)

    i = 0

    # Loop until all text files have been encrypted/decrypted
    while i != 100:
        i = i + 1
        
        filename = "./ciphertexts/"+str(i)
        # Encrypt the message
        encrypted_package = hybrid_encrypt(read_from_file(filename), public_key)
        print("Encrypting ciphertext: "+str(i))


        # Decrypt the message
        hybrid_decrypt(encrypted_package, private_key)
        print("Decrypting ciphertext: "+str(i))
    
    
if __name__ == "__main__":
    main()
