from kyber_py.ml_kem import ML_KEM_512
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import json

def read_from_file(filename):

    # open and read the whole plaintext file
    with open(filename, 'r') as f:
        return str(f.read()) 

def generate_kyber_keypair():
    
    # Generate keypair
    ek, dk = ML_KEM_512.keygen()    
    return ek, dk

def hybrid_kyber_encrypt(message, public_key):

    # Convert message to bytes if it's a string
    if isinstance(message, str):
        message = message.encode('utf-8')

    
    # Use Kyber encapsulate to generate a shared secret and ciphertext
    key, ct = ML_KEM_512.encaps(public_key)    
    # Convert shared secret to proper length for AES-256 (32 bytes)
    # Kyber shared secret is already 32 bytes, but we'll ensure it's the right length
    aes_key = ct[:32]
    
    # Generate a random IV for AES
    iv = os.urandom(16)
    
    # Pad the message to a multiple of 16 bytes (AES block size)
    padder = lambda s: s + (16 - len(s) % 16) * bytes([16 - len(s) % 16])
    padded_message = padder(message)
    
    # Encrypt the message with AES using the shared secret as key
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    
    # Create a package containing all necessary components
    encryption_package = {
        'encrypted_message': base64.b64encode(encrypted_message).decode('utf-8'),
        'kyber_ciphertext': base64.b64encode(ct).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8')
    }
    
    return json.dumps(encryption_package)

def hybrid_kyber_decrypt(encrypted_package, private_key):

    # Parse the encryption package
    package = json.loads(encrypted_package)
    encrypted_message = base64.b64decode(package['encrypted_message'])
    kyber_ciphertext = base64.b64decode(package['kyber_ciphertext'])
    iv = base64.b64decode(package['iv'])
    
    
    # Recover the shared secret using Kyber decapsulate
    _key = ML_KEM_512.decaps(private_key, kyber_ciphertext)    
    # Convert shared secret to proper length for AES-256 (32 bytes)
    aes_key = _key[:32]
    
    # Decrypt the message with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    
    # Unpad the message
    unpadder = lambda s: s[:-s[-1]]
    message = unpadder(padded_message)
    
    return message

def main():
    
    # Generate Kyber key pair
    print("Generating CRYSTAL-KYBER-512 key pair...")
    public_key, private_key = generate_kyber_keypair()

    i = 0
    
    # Loop until all text files have been encrypted/decrypted
    while i != 100:
        i = i + 1
        
        filename = "./ciphertexts/"+str(i)

        # Encrypt the message
        encrypted_package = hybrid_kyber_encrypt(read_from_file(filename), public_key)
        print("Encrypting ciphertext: "+str(i))


        # Decrypt the message
        hybrid_kyber_decrypt(encrypted_package, private_key)
        print("Decrypting ciphertext: "+str(i))
    
if __name__ == "__main__":
    main()
