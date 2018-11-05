import socket
import time
import select
import pickle
from celldef import cell
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import cryptography.hazmat.primitives.asymmetric.padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

socket.socket()
class Server():
    def __init__(self,ip,port,socket):
        self.ip = ip
        self.port = port
        self.socket = socket
        pass

class direct():
    def __init__(self):
        pass

Servers = []
class DirectoryServer():
    def __init__(self):
        self.identities =[]
        for i in range(100):
            self.identities.append(i) #add 1 to 100 for the identities.

        self.socket= socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # tcp type chosen for first.
        # now you have a signature of your own damned public key.
        self.socket.bind(("", 50000))  # better be "" or it'll listen only on localhost
        self.socket.listen(100)

    def mainloop(self):
        while(True):
            readready, _, _ = select.select([self.socket], [], [])
            print("obtained a server connection.")
            (serversocket,myport) = readready[0].accept
            obtained = serversocket.recv(4096) # obtain the data sent over.
            try:
                receivedCell = pickle.loads(obtained)
            except (pickle.PickleError, pickle.PicklingError, pickle.UnpicklingError) as e:
                continue

            if (receivedCell== type(cell(""))): #ensure it is indeed a cell.
                if(cell.type == "giveDirect" ): #
                    signedbytearray= receivedCell.salt
                    signature = receivedCell.signature
                    identity = receivedCell.payload
                    
                    try:
                        tempopen = open("publics/publictest" + str(identity) + ".pem", "rb")
                        theirpublickey = serialization.load_pem_private_key(tempopen.read(), password=None,backend=default_backend())  # used for signing, etc.
                        tempopen.close()
                    except FileNotFoundError:
                        continue #i.e the identity is not established.

                    try:
                        theirpublickey.verify(signature, signedbytearray,
                                    cryptography.hazmat.primitives.asymmetric.padding.PSS(
                                        mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(hashes.SHA256()),
                                        salt_length=cryptography.hazmat.primitives.asymmetric.padding.PSS.MAX_LENGTH),
                                    hashes.SHA256())
                    except InvalidSignature:
                        serversocket.close() #reject. signature validation failed.
                        continue
                    ip,port = serversocket.getpeername() # obtain the ip and port of that server.
                    latest = Server(ip,port,serversocket,identity)
                else:
                    serversocket.close()
                    continue # reject connection as it does not contain a valid cell.




# some directory server.
#receive a connection and dump the list of servers available there?
