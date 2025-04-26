from dilithium_py.dilithium import Dilithium2
import base64

def read_from_file(filename):
    with open(filename, 'r') as f:
        return str(f.read())

# Generate a keypair
pk, sk = Dilithium2.keygen()

i = 0

while i != 100:
    i = i + 1
        
    filename = "./ciphertexts/"+str(i)
    
    ct = read_from_file(filename)

    # Convert message to bytes if it's a string
    if isinstance(ct, str):
        ct = ct.encode('utf-8')

    # Sign the message
    signature = Dilithium2.sign(sk, ct)
    signed_message = signature + ct
    print("Ciphertext signed: "+str(i))

    valid = Dilithium2.verify(pk, ct, signature)

    if valid:
        print("Signature "+str(i)+" verified")
    else:
        print("Signature "+str(i)+" NOT verified")
