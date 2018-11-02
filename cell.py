import pickle

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# PICKLE EXAMPLE
"""
class a:

    def __init__(self,dievalue,bbvalue):
        self.die = dievalue
        self.bb = bbvalue
"""
"""
b = a(1,3)
outfile = open("test","wb")
pickle.dump(b,outfile)
outfile.close()
infile = open("test","rb")
az = pickle.load(infile)

print(az.die)
print(az.bb)
"""
"""
b = a(22,1111)
cc = pickle.dumps(b)
print(len(cc))
z=pickle.loads(cc)
print (z.die)
print (z.bb)
"""