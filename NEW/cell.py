import pickle
import enum
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class cell():
    _Types= enum.Enum("Cells","AddCon Req Resp")

    def __init__(self,isconnection,isreq,payload,IV=None,salt=None,signature = None):

        if(isconnection):
            self.type = self._Types.AddCon  # is a connection request. so essentially some key is being pushed out here.
        else:
            if(isreq):
                self.type = self._Types.Req   # is a request.
            else:
                self.type = self._Types.Resp
        if(self.type ==self._Types.Req):
            self.payload = payload
        else:  # is a connection request or response...
            if(self.type == self._Types.Resp): #is a response. Requires a signature.
                self.signature = signature
            self.payload = payload  # in this case, it should contain some public key in byte form.
            self.IV = IV  # save the IV since it's a connection cell.
            if (salt != None):
                self.salt = salt


    def dump(self): #to return a byte representation of this.
        return pickle.dumps(self)


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