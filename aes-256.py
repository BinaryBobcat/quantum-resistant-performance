from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def generate_key_and_iv():
    key = os.urandom(32)
    iv = os.urandom(16)

    return key, iv

def read_from_file(filename):
    with open(filename, 'r') as f:
        return str(f.read())            

def encrypt(plaintext, key, iv):
    
    # Convert plaintext to bytes if it's a string
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Pad the plaintext to a multiple of 16 bytes (AES block size)
    padder = lambda s: s + (16 - len(s) % 16) * bytes([16 - len(s) % 16])
    padded_plaintext = padder(plaintext)
    
    # Create an encryptor object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return ciphertext

def decrypt(ciphertext, key, iv):
    # Create a decryptor object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad the plaintext
    unpadder = lambda s: s[:-s[-1]]
    plaintext = unpadder(padded_plaintext)
    
    return plaintext

def main():
    # Generate AES-256 key and IV
    key, iv = generate_key_and_iv()
    
    i = 0

    while i != 100:
        i = i + 1
        
        filename = "./ciphertexts/"+str(i)

        # Encrypt the message
        encrypted_message = encrypt(read_from_file(filename), key, iv)
        print("Encrypting ciphertext: "+str(i))

        # Decrypt the message
        decrypt(encrypted_message, key, iv)
        print("Decrypting ciphertext: "+str(i))

if __name__ == "__main__":
    main()