from socket import *
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import requests
import cryptography.hazmat.primitives.asymmetric.padding
from struct import *
from random import randint
import pickle
import os
import select
from celldef import cell


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
        reply_cell = cell(serialised_public_key,salt = salty,Type="ConnectResp")
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
                    if(obtainedCell.type != "AddCon"):
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
                except (error, ConnectionResetError,ConnectionAbortedError )as e:

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
                if(cell_to_next.type == "relay connect"): #is a request for a relay connect
                    try:
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
                            encrypted = encryptor.update(self.padder128(pickle.dumps(cell("",Type = "failed"))))
                            encrypted += encryptor.finalize()
                            print("sent failed")
                            i.send(pickle.dumps(cell(encrypted, IV=IV, Type="failed")))
                        else:
                            encrypted = encryptor.update(self.padder128(pickle.dumps(cell(theircell,Type = "ConnectResp"))))
                            encrypted += encryptor.finalize()
                            print("sent valid response")
                            i.send(pickle.dumps(cell(encrypted,IV=IV,Type = "AddCon")))
                            clientWhoSent.bounceIP = cell_to_next.ip
                            clientWhoSent.bouncePORT = cell_to_next.port
                            clientWhoSent.bounceSocket = sock
                            print("connection success.\n\n\n\n\n")
                    except (ConnectionRefusedError,ConnectionResetError,ConnectionAbortedError,error)as e:
                        print("failed to connect to other server. sending back failure message.")
                        IV = os.urandom(16)
                        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(IV), backend=default_backend())
                        encryptor = cipher.encryptor()
                        encrypted = encryptor.update(self.padder128(pickle.dumps(cell(pickle.dumps(cell("CONNECTIONREFUSED", Type="failed")),Type = "failed"))))
                        encrypted += encryptor.finalize()
                        i.send(pickle.dumps(cell(encrypted, IV=IV, Type="failed")))
                        print("sent back failure message.")

                elif (cell_to_next.type =="relay"):  # is an item to be relayed.
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
                        theircell = sock.recv(32768)  # await answer
                        print("got answer back.. as a relay.")
                        print(len(theircell))
                        print(theircell)
                        IV = os.urandom(16)
                        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(IV), backend=default_backend())
                        encryptor = cipher.encryptor()
                        encrypted = encryptor.update(
                            self.padder128(pickle.dumps(cell(theircell, Type = "ConnectResp"))))
                        encrypted += encryptor.finalize()
                        i.send(pickle.dumps(cell(encrypted, IV=IV, Type = "AddCon")))
                        print("Relay success.\n\n\n\n\n")
                elif(cell_to_next.type == "Req"):
                    print(cell_to_next.payload)
                    if(type(cell_to_next.payload)!=type("") ):
                        IV=os.urandom(16)
                        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(IV), backend=default_backend())
                        encryptor = cipher.encryptor()
                        encrypted = encryptor.update(self.padder128(pickle.dumps(cell("INVALID REQUEST DUMDUM", Type = "ConnectResp"))))
                        encrypted += encryptor.finalize()
                        i.send(pickle.dumps(cell(encrypted, IV=IV, Type = "AddCon")))
                        print("INVALID REQUEST SENT BACK")
                    else:
                        request =cell_to_next.payload
                        a = requests.get(request)
                        print("length of answer")
                        print(len(a.content))
                        IV = os.urandom(16)
                        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(IV), backend=default_backend())
                        encryptor = cipher.encryptor()
                        encrypted = encryptor.update(
                            self.padder128(pickle.dumps(cell(pickle.dumps(a), Type = "ConnectResp"))))
                        encrypted += encryptor.finalize()
                        i.send(pickle.dumps(cell(encrypted, IV=IV, Type = "AddCon")))
                        print("VALID REQUEST REPLIED.")



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
