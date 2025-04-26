import sys
sys.path.append('./algs/python-mceliece/src/')
import mceliece


kem = mceliece.mceliece6960119
pk,sk = kem.keypair()
c,k = kem.enc(pk)
assert k == kem.dec(c,sk)
print(c)