import sys
sys.path.append('./algs/falcon.py/')

import falcon

def read_from_file(filename):
    
    # open and read the whole plaintext file
    with open(filename, 'r') as f:
        return str(f.read())


# Generate Falcon-512 key pair
sk = falcon.SecretKey(512)
pk = falcon.PublicKey(sk)

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
    signature = sk.sign(ct)

    # Verify the signature
    is_valid = pk.verify(ct, signature)

    if is_valid:
        print("Signature "+str(i)+" is valid!")
    else:
        print("Signature "+str(i)+" is invalid.")
