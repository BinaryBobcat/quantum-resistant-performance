from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


def read_from_file(filename):

    # open and read the whole plaintext file
    with open(filename, 'r') as f:
        return str(f.read())   

def generate_key_and_iv():

    # Generate key and IV from urandom
    key = os.urandom(24)
    iv = os.urandom(8)

    return key, iv

def encrypt(plaintext, key, iv):

    # making sure the input is utf-8
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # padding plaintext
    padder = lambda s: s + (8 - len(s) % 8) * bytes([8 - len(s) % 8])
    padded_plaintext = padder(plaintext)
    
    # Create an encryptor object
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return ciphertext

def decrypt(ciphertext, key, iv):

    # Create a decryptor object
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad the plaintext
    unpadder = lambda s: s[:-s[-1]]
    plaintext = unpadder(padded_plaintext)
    
    return plaintext

def main():
   
    # Generate key and IV
    key, iv = generate_key_and_iv()
    
    i = 0

    # looping until all text files have been encrypted and decrypted
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
