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
class Serverreg():
    def __init__(self,ip,port,socket):#,latency):
        self.ip = ip
        self.port = port
        self.socket = socket
        #self.latency = latency

class DirectoryServer():
    def __init__(self):
        self.lasttime = time.time()
        self.registered_servers = []
        self.socketlist = []
        self.identities = []
        for i in range(100):
            self.identities.append(i) #add 1 to 100 for the identities.

        self.socket= socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # tcp type chosen for first.
        # now you have a signature of your own damned public key.
        self.socket.bind(("", 50000))  # better be "" or it'll listen only on localhost
        self.socket.listen(100)

    def mainloop(self):
        while(True):
            """if ((time.time() - self.lasttime) > 20.00):
                for i in self.registered_servers:
                    i.time = time.time()
                    i.socket.send(cell("",Type= "checkup"))
                    
            else:
            """
            #SOME INDENTATION.
            readready, _, _ = select.select([self.socket]+self.socketlist, [], [])
            print("obtained a server connection.")
            for i in readready:
                if(i==self.socket): #is receiving a new connection request.
                    (serversocket,myport) = readready[0].accept
                    obtained = serversocket.recv(4096) # obtain the data sent over.
                    try:
                        receivedCell = pickle.loads(obtained)
                    except (pickle.PickleError, pickle.PicklingError, pickle.UnpicklingError) as e:
                        continue

                    if (type(receivedCell)== type(cell(""))): #ensure it is indeed a cell.
                        if(receivedCell.type == "giveDirect" ): #
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
                            ##
                            """
                            firstlatency = time.time()
                            serversocket.send(cell("",Type="checkup"))
                            serversocket.recv(4096)
                            secondlatency = time.time()
                            latency = secondlatency-firstlatency
                            """
                            self.registered_servers.append(Serverreg(ip,port,serversocket,identity,latency))
                        else:
                            serversocket.close()
                            continue # reject connection as it does not contain a valid cell.
                else:
                    print("got from existing.")
                    received = i.recv(4096)
                    for k in self.registered_servers:
                        if (k.socket == i):
                            # i.e it is part of the thing.
                            reference = k
                    if (len(received) == 0): #disconnect catch
                        print("CLIENT WAS CLOSED! or timed out.")
                        i.socket.close()
                        self.registered_servers.remove(reference)
                        continue

                    """else: #am currently receiving an update
                        now = time.time()
                        for k in self.registered_servers:
                            if(k.socket == i):
                                #i.e it is part of the thing.
                                reference = k
    
                        rtt = now -reference.time
                        reference.latency = rtt #save the latency
                    """







# some directory server.
#receive a connection and dump the list of servers available there?
