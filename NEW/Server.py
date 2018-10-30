from socket import *
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import enum
from struct import *
from random import randint
import pickle
import os
import select


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


class client():
    def __init__(self,sock,key,generatedKey):
        self.socket = sock
        self.key = key # the derived key
        self.generatedKey= generatedKey #the generated elliptic curve diffie hellman key.
        self.bounceIP = None
        self.bouncePORT = None
        self.bounceSocket=None
        #self.theirpublickey = theirpublickey


class Server():
    CLIENTS = []
    CLIENTSOCKS = []

    def __init__(self,portnumber,identity):
        tempopen =open("privates/privatetest"+str(identity)+".pem","rb")
        self.TRUEprivate_key =serialization.load_pem_private_key(tempopen.read(), password=None, backend=default_backend())#used for signing, etc.
        self.sendingpublickey = self.TRUEprivate_key.public_key()  # public key for sending out.
        self.serversocket = socket(AF_INET, SOCK_STREAM)  # tcp type chosen for first.
        #now you have a signature of your own damned public key.
        self.serversocket.bind(("", portnumber))  # better be "" or it'll listen only on localhost
        self.serversocket.listen(100)



    def ExchangeKeys(self,clientsocket,obtainedCell):
        # Exchange Key with someone, obtaining a shared secret. Also, generate salt
        # and pass it back to them with your private key.
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())  # elliptic curve
        public_key = private_key.public_key()  # duh same.
        serialised_public_key = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
        # serialise the public key that I'm going to send them

        theirkey = serialization.load_pem_public_key(obtainedCell.payload, backend=default_backend())
        shared_key = private_key.exchange(ec.ECDH(), theirkey)
        salty = str.encode(str(randint(0, 99999999)))  # randomised IV
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salty, info=None, backend=default_backend()).derive(shared_key)
        reply_cell = cell(True,False,serialised_public_key,salt = salty)

        signature = self.TRUEprivate_key.sign(reply_cell, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        reply_cell.signature = signature #assign the signature.

        clientsocket.send(pickle.dumps(reply_cell))  # send them the serialised version.
        return private_key,derived_key


    def decrypt(self,thing):  # thing that is in RSA encryption must be decrypted before continuing.
        self.TRUEprivate_key.decrypt(thing, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None))

    def main(self):
        clientclass = None  # initialise as none.
        readready, _, _ = select.select([self.serversocket] + self.CLIENTSOCKS, [], [])
        for i in readready:
            print("some")
            if (i == self.serversocket):  # i've gotten a new connection
                print("client get")
                (clientsocket, address) = self.serversocket.accept()
                try:
                    obtainedCell = clientsocket.recv(4096)  # obtain their public key
                    obtainedCell = self.decrypt(obtainedCell) #decrypt the item.
                    obtainedCell = pickle.loads(obtainedCell) # i.e grab the cell that was passed forward.
                    if(obtainedCell.type != obtainedCell._Types.AddCon):
                        break # it was not a connection request.
                    generatedPrivateKey,derivedkey= self.ExchangeKeys(clientsocket,obtainedCell) #obtain the generated public key, and the derived key.
                    clientclass = client(clientsocket, derivedkey, generatedPrivateKey)
                    self.CLIENTS.append(clientclass)
                    self.CLIENTSOCKS.append(clientsocket)
                    print("Connected to ONE client.")

                except error: #error is socket error here.
                    if (clientclass != None):
                        self.CLIENTS.remove(clientclass)
                        # just in case.
                        #otherwise, it should continue
                    continue

            else:  # came from an existing client.
                try:
                    received = i.recv(4096)
                    for k in self.CLIENTS:
                        if (k.socket == i):
                            clientWhoSent = k
                except error:
                    continue
                if (len(received) == 0):
                    print("CLIENT WAS CLOSED!")

                    self.CLIENTSOCKS.remove(i)
                    self.CLIENTS.remove(clientWhoSent)
                else:
                    received_data = self.decrypt(received)
                    gottencell = pickle.loads(received_data)
                    if(gottencell.type == gottencell._Types.AddCon): #is a request for forwarding.
                        derived_key = clientWhoSent.key  # take his derived key
                        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(gottencell.IV), backend=default_backend())
                        decryptor = cipher.decryptor()
                        decrypted = decryptor.update(gottencell.payload)
                        decrypted+= decryptor.finalize()
                        cell_to_next = pickle.loads(decrypted)
                        sock = socket(AF_INET, SOCK_STREAM)  # your connection is TCP.
                        sock.connect((cell_to_next.ip, cell_to_next.port))
                        sock.send(decrypted)  # send over the cell
                        theircell = sock.recv(4096)  # await answer

                        pass  #i am passing on the message.
                    else:

                        pass #i am the last hop. the requester.
















                    """print("total received length")
                    print(len(received))
                    print(received)"""
                    # iv = received[-48:-32] #before last 32 is iv
                    # ip = received[-32:] #last 32 elements
                    ##iv = received[-16:]  # last 16 bits are now the iv.
                    ##everythingelse = received[:-16]
                    ##print("length of encrypted")
                    ##print(len(everythingelse))
                    ##print("encrypted")
                    ##print(everythingelse)
                    """print("length of ip bytes (they refer to me though..)")
                    print(len(ip))
                    print("ip bytes (my ip, in byte form. duh.)")
                    print(ip)"""
                    """print("length of iv bytes")
                    print(len(iv))
                    print("iv bytes")
                    print(iv)"""
                    ##clientwhosent = None
                    ##for k in self.CLIENTS:
                        ##if (k.socket == i):
                            ##clientwhosent = k
                    ##if (clientwhosent == None):
                        ##continue  # was a spoofed packet
                    ##try:
                        ##cipher = Cipher(algorithms.AES(clientwhosent.key), modes.CBC(iv), backend=default_backend())
                        ##AESdecryptor = cipher.decryptor()
                        ##decrypted = AESdecryptor.update(everythingelse)
                        ##decrypted += AESdecryptor.finalize()
                        ##unpadder = padding.PKCS7(256).unpadder()  # IP is padded to 256
                        ##decrypted = self.TRUEprivate_key.decrypt(decrypted, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                        ##print("len decrypted " + str(len(decrypted)))
                        ##print("decrypted bytes")
                        ##print(decrypted)
                        ##u = unpadder.update(decrypted[-32:])  # ATTEMPT TO STRIP THE IP AT THE LAST 32 BITS
                        ##u += unpadder.finalize()
                        ##print("I AM NOT THE LAST HOP.")
                        ##print(str(u))
                        ##print("length of bytes of next hop bytes " + str(len(u)))
                        ##print("bytes of next hop")
                        ##print(u)
                        ##print("target of next hop")
                        ##print(str(u))  # this is the next ip hop.
                        # send decrypted[:-32] i.e. without the ip address. Ensure it is wrapped in a AES with the next server. don't forget to include iv.
                        ##i.send("h")
                        ##for k in self.CLIENTS:
                            ##if (k.socket == i):
                                ##clienttoremove = k
                        ##self.CLIENTSOCKS.remove(i)
                        ##self.CLIENTS.remove(clienttoremove)  # close the connection and kick them out.
                        ##i.close()  # now close and leave.
                        ##self.BounceToOtherServer(str(u), decrypted[:-32])  # without the IP Address.
                    ##except ValueError:
                        ##print("AM THE LAST ONE! AM THE LAST ONE!")
                        ##IPofSender = str(decrypted)[-247:-215]
                        ##originalPEM = str(decrypted)[-215:]
                        ##print("requesting" + str(decrypted)[:-32])
                        ##sendback = requests.get(decrypted)  # obtained the data
                        ##originalpublickey = serialization.load_pem_public_key(IPofSender, password=None,backend=default_backend())  # load pem public key here.
                        # now do the same thing as a client and select 3 things to send...
                        # no other padding is required.
                        # DO SOMETHING WITH THE DATA


portnumber = input("give portnum pls\n")
server = Server(portnumber,0)
while True:
    server.main()
