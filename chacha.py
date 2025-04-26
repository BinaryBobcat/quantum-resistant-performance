from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.backends import default_backend
import os

def read_from_file(filename):

    # open and read the whole plaintext file
    with open(filename, 'r') as f:
        return str(f.read())   

def generate_key_and_nonce():

    # Generate random keys and ivs 
    key = os.urandom(32)
    nonce = os.urandom(16)

    return key, nonce

def encrypt(plaintext, key, nonce):

    # making sure input is utf-8
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Initialize the ChaCha20 cipher with key and nonce
    cipher = Cipher(ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the plaintext
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return ciphertext

def decrypt(ciphertext, key, nonce):

    # Initialize the ChaCha20 cipher with the same key and nonce
    cipher = Cipher(ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext

def main():
  
    key, nonce = generate_key_and_nonce()
    
    i = 0

    # looping until all text files have been encrypted and decrypted
    while i != 100:
        i = i + 1
        
        filename = "./ciphertexts/"+str(i)
        # Encrypt the message
        encrypted_message = encrypt(read_from_file(filename), key, nonce)
        print("Encrypting ciphertext: "+str(i))
    
        # Decrypt the message
        decrypt(encrypted_message, key, nonce)
        print("Decrypting ciphertext: "+str(i))
    
if __name__ == "__main__":
    main()
