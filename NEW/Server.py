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
import cryptography.hazmat.primitives.asymmetric.padding
from struct import *
from random import randint
import pickle
import os
import select

class cell():
    _Types = ["AddCon", "Req", "ConnectResp", "FAILED", "relay connect","relay"]

    def __init__(self, isconnection, isreq, payload, IV=None, salt=None, signature=None, Type =None):
        if (isconnection):
            self.type = self._Types[0]  # is a connection request. so essentially some key is being pushed out here.
        else:
            if (isreq):
                self.type = self._Types[1]  # is a request.
            else: #is connec , is NOT a request
                self.type = self._Types[2] #is a response to a connection

        if (self.type == self._Types[1]):
            self.payload = payload
        else:  # is a connection request or response...
            if (self.type == self._Types[2]):  # is a response. Requires a signature.
                self.signature = signature
            self.payload = payload  # in this case, it should contain some public key in byte form.
            self.IV = IV  # save the IV since it's a connection cell.
            if (salt != None):
                self.salt = salt
        if (Type != None):
            if (Type == "failed"):
                self.type = self._Types[3]  # indicates failure
            else:
                if(Type =="relay connect"):
                    self.type = self._Types[4]  # indicates to make a connection to a new server.
                else:
                    self.type = self._Types[5] #indicates relay


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

    def padder256(self, data):
        padder1b = padding.PKCS7(256).padder()  # pad ip to 256 bits... because this can vary too...
        p1b = padder1b.update(data)
        p1b += padder1b.finalize()
        return p1b

    def padder128(self, data):
        padder1b = padding.PKCS7(128).padder()  # pad ip to 256 bits... because this can vary too...
        p1b = padder1b.update(data)
        p1b += padder1b.finalize()
        return p1b

    def unpadder128(self, data):
        padder1b = padding.PKCS7(128).unpadder()  # pad ip to 256 bits... because this can vary too...
        p1b = padder1b.update(data)
        p1b += padder1b.finalize()
        return p1b

    def unpadder256(self, data):
        padder1b = padding.PKCS7(256).unpadder()  # pad ip to 256 bits... because this can vary too...
        p1b = padder1b.update(data)
        p1b += padder1b.finalize()
        return p1b

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
        reply_cell = cell(False,False,serialised_public_key,salt = salty)
        signature = self.TRUEprivate_key.sign(salty,
                                              cryptography.hazmat.primitives.asymmetric.padding.PSS(
                                                  mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(hashes.SHA256()),
                                                  salt_length=cryptography.hazmat.primitives.asymmetric.padding.PSS.MAX_LENGTH),hashes.SHA256())
        reply_cell.signature = signature #assign the signature.
        print("reply cell")
        print(pickle.dumps(reply_cell))
        clientsocket.send(pickle.dumps(reply_cell))  # send them the serialised version.
        return private_key,derived_key


    def decrypt(self,thing):  # thing that is in RSA encryption must be decrypted before continuing.
        return self.TRUEprivate_key.decrypt(thing,cryptography.hazmat.primitives.asymmetric.padding.OAEP(
            mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None))

    def main(self):
        clientclass = None  # initialise as none.
        readready, _, _ = select.select([self.serversocket] + self.CLIENTSOCKS, [], [])
        for i in readready:
            if (i == self.serversocket):  # i've gotten a new connection
                print("client get")
                (clientsocket, address) = self.serversocket.accept()
                try:
                    obtainedCell = clientsocket.recv(4096)  # obtain their public key
                    try:
                        print("raw data obtained. (Cell)")
                        print(obtainedCell)
                        obtainedCell = self.decrypt(obtainedCell) #decrypt the item.

                    except(ValueError)as e: #this is due to decryption failure.
                        if (clientclass != None):
                            self.CLIENTS.remove(clientclass)
                            # just in case.
                            # otherwise, it should continue
                        print("rejected one connection")
                        continue
                    print("decrypted cell with actual keys.")
                    print(obtainedCell)
                    obtainedCell = pickle.loads(obtainedCell) # i.e grab the cell that was passed forward.
                    print("after pickle load")
                    print(obtainedCell)
                    if(obtainedCell.type != obtainedCell._Types[0]):
                        break  # it was not a connection request.
                    generatedPrivateKey,derivedkey= self.ExchangeKeys(clientsocket,obtainedCell) #obtain the generated public key, and the derived key.
                    clientclass = client(clientsocket, derivedkey, generatedPrivateKey)
                    self.CLIENTS.append(clientclass)
                    self.CLIENTSOCKS.append(clientsocket)
                    print(clientclass.socket.getpeername())
                    print("Connected to ONE client.\n\n\n")

                except (error,ConnectionResetError )as e: #error is socket error here.
                    print("socket ERROR")
                    if (clientclass != None):
                        self.CLIENTS.remove(clientclass)
                        # just in case.
                        #otherwise, it should continue
                    continue

            else:  # came from an existing client.
                try:
                    for k in self.CLIENTS:
                        if (k.socket == i):
                            clientWhoSent = k
                    received = i.recv(4096)
                    print("got a packet..")
                    print(received)
                    if(len(received)==0):
                        raise ConnectionResetError
                except (error, ConnectionResetError )as e:

                    print("CLIENT WAS CLOSED!")
                    clientWhoSent.socket.close()
                    if(clientWhoSent.bounceSocket!=None):
                        clientWhoSent.bounceSocket.close()
                    self.CLIENTSOCKS.remove(i)
                    self.CLIENTS.remove(clientWhoSent)
                    continue
                print("existing")
                # received_data = self.decrypt(received)
                gottencell = pickle.loads(received)
                derived_key = clientWhoSent.key  # take his derived key
                cipher = Cipher(algorithms.AES(derived_key), modes.CBC(gottencell.IV), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(gottencell.payload)
                decrypted += decryptor.finalize()
                cell_to_next = pickle.loads(decrypted)
                print(cell_to_next.type)
                if(cell_to_next.type == cell_to_next._Types[4]): #is a request for a relay connect
                    sock = socket(AF_INET, SOCK_STREAM)  # your connection is TCP.
                    sock.connect((cell_to_next.ip, cell_to_next.port))
                    print((cell_to_next.ip, cell_to_next.port))
                    print("cell to next")
                    print(decrypted)
                    print("payload")
                    print(cell_to_next.payload)
                    sock.send(cell_to_next.payload)  # send over the cell payload
                    theircell = sock.recv(4096)  # await answer
                    print("got values")
                    print(theircell)
                    IV = os.urandom(16)
                    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(IV), backend=default_backend())
                    encryptor = cipher.encryptor()
                    if(theircell==b""):
                        encrypted = encryptor.update(self.padder128(pickle.dumps(cell(False,False,"",Type = "failed"))))
                        encrypted += encryptor.finalize()
                        print("sent failed")
                        i.send(pickle.dumps(cell(False, False, encrypted, IV=IV, Type="failed")))
                    else:
                        encrypted = encryptor.update(self.padder128(pickle.dumps(cell(False,False,theircell))))
                        encrypted += encryptor.finalize()
                        print("sent valid response")
                        i.send(pickle.dumps(cell(True,False,encrypted,IV=IV)))
                        clientWhoSent.bounceIP = cell_to_next.ip
                        clientWhoSent.bouncePORT = cell_to_next.port
                        clientWhoSent.bounceSocket = sock
                        print("connection success.\n\n\n\n\n")

                    pass  #i am passing on the message.
                elif (cell_to_next.type == cell_to_next._Types[5]):  # is an item to be relayed.
                    if(clientWhoSent.bounceSocket==None): #check if there is bounce socket
                        return
                    else:
                        sock = clientWhoSent.bounceSocket
                        print("bouncing cell's decrypted..")
                        print(decrypted)
                        print("payload")
                        print(cell_to_next.payload)
                        print(cell_to_next.type)
                        sock.send(cell_to_next.payload) # send over the cell
                        theircell = sock.recv(4096)  # await answer
                        print("got answer back.. as a relay.")
                        print(theircell)
                        IV = os.urandom(16)
                        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(IV), backend=default_backend())
                        encryptor = cipher.encryptor()
                        encrypted = encryptor.update(
                            self.padder128(pickle.dumps(cell(False, False, theircell))))
                        encrypted += encryptor.finalize()
                        i.send(pickle.dumps(cell(True, False, encrypted, IV=IV)))
                        print("Relay success.\n\n\n\n\n")
                elif(cell_to_next.type == cell_to_next._Types[1]):
                    print(cell_to_next.payload)
                    IV=os.urandom(16)
                    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(IV), backend=default_backend())
                    encryptor = cipher.encryptor()
                    encrypted = encryptor.update(self.padder128(pickle.dumps(cell(False, False,"12345"))))
                    encrypted += encryptor.finalize()
                    i.send(pickle.dumps(cell(True, False, encrypted, IV=IV)))

















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


portnumber = input("give portnum pls a = 45000 b = 45001 c =45002\nelse i default to 45003\n")
if(portnumber =="a"):
    print("am 45000")
    server = Server(45000,0)
else:
    if (portnumber == "b"):
        print("am 45001")
        server = Server(45001, 1)
    else:
        if (portnumber == "c"):
            print("am 45002")
            server = Server(45002, 2)
        else:
            print("am 45002")
            server = Server(45003, 2)

while True:
    server.main()
