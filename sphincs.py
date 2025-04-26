import pyspx.shake_128f as sphincs  
import os

def read_from_file(filename):

    # open and read the whole plaintext file
    with open(filename, 'r') as f:
        return str(f.read())

# seed urandom with 48 for reliable randomness
seed = os.urandom(48)

# generate private and shared key using the library
pk, sk = sphincs.generate_keypair(seed)

i = 0

# Loop until all text files have been encrypted/decrypted
while i != 100:
    i = i + 1
        
    filename = "./ciphertexts/"+str(i)
    
    ct = read_from_file(filename)

    # Convert message to bytes if it's a string
    if isinstance(ct, str):
        ct = ct.encode('utf-8')

    # Sign the message
    signature = sphincs.sign(ct, sk)

    # Verify the signature
    valid = sphincs.verify(ct, signature, pk)

    if valid:
        print("Signature "+str(i)+" is valid!")
    else:
        print("Signature "+str(i)+" is invalid.")
