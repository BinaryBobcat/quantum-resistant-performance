import sys
sys.path.append('./algs/python-mceliece/src/')
import mceliece
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def read_from_file(filename):
    
    # open and read the whole plaintext file
    with open(filename, 'r') as f:
        return f.read().strip()  # remove newlines if any

# setting kem = to the specific mcecliece alg
kem = mceliece.mceliece6960119

# generating a keypair using the library
pk, sk = kem.keypair()

# Loop until all text files have been encrypted/decrypted
for i in range(1, 101):
    filename = f"./ciphertexts/{i}"
    
    ct_plaintext = read_from_file(filename)

    # Convert message to bytes
    ct_bytes = ct_plaintext.encode('utf-8')

    # Step 1: Generate shared secret using McEliece KEM
    ciphertext, shared_secret_enc = kem.enc(pk)

    # Step 2: Encrypt the file content using AES-GCM with the shared secret
    aes_key = shared_secret_enc[:32]  # Use 256 bits (32 bytes) from shared secret
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # AES-GCM requires 12-byte nonce
    encrypted_data = aesgcm.encrypt(nonce, ct_bytes, None)
    print("Encrypting ciphertext: "+str(i))


    # Step 3: Decapsulate to get the same shared secret
    shared_secret_dec = kem.dec(ciphertext, sk)

    # Step 4: Decrypt the data using AES-GCM and decapsulated secret
    aes_key = shared_secret_dec[:32]
    aesgcm = AESGCM(aes_key)
    decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
    print("Decrypting ciphertext: "+str(i))
