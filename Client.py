from socket import *
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import cryptography.hazmat.primitives.asymmetric.padding
import os
import pickle
from struct import *
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from celldef import cell


class Server():
    def __init__(self,ip,socket,derivedkey,ec_key,theirRSA,port):
        self.ip = ip
        self.socket =  socket
        self.key = derivedkey
        self.ec_key = ec_key
        self.theirRSA = theirRSA
        self.port = port

class Client():
    serverList=[]
    def __init__(self):

        # generate public private key pair
        self.private_key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=3072) #RSA
        self.public_key = self.private_key.public_key()
        self.serialised_public_key = self.public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        #serialised RSA public key.

    def makeFirstConnectCell(self):
        ECprivate_key = ec.generate_private_key(ec.SECP384R1(), default_backend())  # elliptic curve
        DHpublicKeyBytes = ECprivate_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)
        sendingCell = cell(DHpublicKeyBytes, Type="AddCon")  # send the initialising cell, by sending the DHpublicKeyBytes
        return sendingCell,ECprivate_key

    def padder256(self,data):
        padder1b = padding.PKCS7(256).padder()  # pad ip to 256 bits... because this can vary too...
        p1b = padder1b.update(data)
        p1b += padder1b.finalize()
        return p1b

    def padder128(self,data):
        padder1b = padding.PKCS7(128).padder()  # pad ip to 256 bits... because this can vary too...
        p1b = padder1b.update(data)
        p1b += padder1b.finalize()
        return p1b

    def firstConnect(self,gonnect,gonnectport,theirRSApublic):
        #you should already HAVE their public key.
        try:
            sock = socket(AF_INET, SOCK_STREAM)  # your connection is TCP.
            sock.connect((gonnect,gonnectport))
            sendingCell,ECprivate_key = self.makeFirstConnectCell()
            #key encryption for RSA HERE USING SOME PUBLIC KEY
            readiedcell = pickle.dumps(sendingCell)
            print("first connect Actual cell (encrypted bytes) ")
            print(readiedcell)
            encryptedCell = theirRSApublic.encrypt(readiedcell,cryptography.hazmat.primitives.asymmetric.padding.OAEP(
                mgf = cryptography.hazmat.primitives.asymmetric.padding.MGF1(algorithm=hashes.SHA256()),algorithm = hashes.SHA256(),label = None))
            print("first connect Actual cell(decrypted bytes)")
            print(encryptedCell)
            sock.send(encryptedCell)  # send my public key... tcp style
            theircell= sock.recv(4096)
            theircell = pickle.loads(theircell) #load up their cell
            print(theircell.type)
            signature = theircell.signature #this cell isn't encrypted. Extract the signature to verify
            try:
                theirRSApublic.verify(signature,theircell.salt,
                                      cryptography.hazmat.primitives.asymmetric.padding.PSS(
                                          mgf = cryptography.hazmat.primitives.asymmetric.padding.MGF1(hashes.SHA256()),
                                          salt_length = cryptography.hazmat.primitives.asymmetric.padding.PSS.MAX_LENGTH),hashes.SHA256())
                #verify that the cell was signed using their key.
                theirKey = serialization.load_pem_public_key(theircell.payload,backend=default_backend())  # load up their key.

                shared_key = ECprivate_key.exchange(ec.ECDH(), theirKey)
                derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=theircell.salt, info=None,backend=default_backend()).derive(shared_key)
                #cipher = Cipher(algorithms.AES(derived_key), modes.CBC(IV), backend=default_backend()) #256 bit length cipher lel
                #encryptor = cipher.encryptor()
                #ct = encryptor.update() + encryptor.finalize()
                # decryptor = cipher.decryptor()
                # decryptor.update(ct) + decryptor.finalize()

                #Connection is established at this point.

                print("connected successfully to server @ " + gonnect + "   Port: " + str(gonnectport))
                self.serverList.append(Server(gonnect, sock, derived_key, ECprivate_key,theirRSApublic,gonnectport))
                return   # a server item is created.

            except InvalidSignature:
                print("Something went wrong.. Signature was invalid.")
                return None

        except (error ,ConnectionResetError)as e:
            print("disconnected or server is not online/ connection was refused.")

    def moreConnect1(self,gonnect,gonnectport,list_of_Servers_between,theirRSA):
        print("MORE CONNECT 1")
        #must send IV and a cell that is encrypted with the next public key
        #public key list will have to be accessed in order with list of servers.
        #number between is to know when to stop i guess.
        sendingCell, ECprivate_key = self.makeFirstConnectCell()
        sendingCell=pickle.dumps(sendingCell)
        print("Innermost cell with keys")
        print(sendingCell)
        sendingCell = theirRSA.encrypt(sendingCell, cryptography.hazmat.primitives.asymmetric.padding.OAEP(
            mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None))
        print("Innermost cell with keys (Encrypted)")
        print(sendingCell)
        sendingCell = cell(sendingCell,Type="relay connect") #connection type. exit node always knows
        sendingCell.ip = gonnect
        sendingCell.port = gonnectport  # save the stuff i should be sending over.
        IV = os.urandom(16)

        cipher = Cipher(algorithms.AES(list_of_Servers_between[0].key), modes.CBC(IV),backend=default_backend())  # 256 bit length cipher lel
        encryptor = cipher.encryptor() #encrypt the entire cell
        encrypted = encryptor.update(self.padder128(pickle.dumps(sendingCell)))
        encrypted+= encryptor.finalize() #finalise encryption.
        sendingCell = cell(encrypted,IV= IV,Type="relay connect")


        try:
            sock = list_of_Servers_between[0].socket
            sock.send(pickle.dumps(sendingCell)) # send over the cell
            print("cell sent: ")
            print(pickle.dumps(sendingCell))
            theircell = sock.recv(4096) # await answer
            #you now receive a cell with encrypted payload.
            counter =len(list_of_Servers_between)-1
            theircell = pickle.loads(theircell)
            if(theircell.type==theircell._Types[3]):
                print("FAILED AT CONNECTION!")
                return
            while(counter>=0):
                cipher = Cipher(algorithms.AES(list_of_Servers_between[counter].key),modes.CBC(theircell.IV),backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(theircell.payload)
                decrypted += decryptor.finalize() #finalise decryption
                print(decrypted)
                theircell = pickle.loads(decrypted)
                counter-=1
                theircell = pickle.loads(theircell.payload)
            #theircell = pickle.loads(theircell.payload)

            signature = theircell.signature  # this cell isn't encrypted. Extract the signature to verify
            theircell.signature = None
            theirRSA.verify(signature, theircell.salt,
                                  cryptography.hazmat.primitives.asymmetric.padding.PSS(
                                      mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(hashes.SHA256()),
                                      salt_length=cryptography.hazmat.primitives.asymmetric.padding.PSS.MAX_LENGTH),
                                  hashes.SHA256())
            # verify that the cell was signed using their key.
            # at this point, you have the cell that is the public key of your target server. Additionally, salt too..
            theirKey = serialization.load_pem_public_key(theircell.payload,backend=default_backend())  # load up their key.
            shared_key = ECprivate_key.exchange(ec.ECDH(), theirKey)
            derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=theircell.salt, info=None,backend=default_backend()).derive(shared_key)
            self.serverList.append(Server(gonnect, sock, derived_key, ECprivate_key, theirRSA, gonnectport))
            print("connected successfully to server @ " + gonnect + "   Port: " + str(gonnectport))
        except error:
            print("socketerror")


    def moreConnect2(self, gonnect, gonnectport, list_of_Servers_between, theirRSA):
        print("MORE CONNECT 2")
        # must send IV and a cell that is encrypted with the next public key
        # public key list will have to be accessed in order with list of servers.
        # number between is to know when to stop i guess.
        sendingCell, ECprivate_key = self.makeFirstConnectCell()
        sendingCell = pickle.dumps(sendingCell)
        print("Innermost cell with keys")
        print(sendingCell)
        sendingCell = theirRSA.encrypt(sendingCell, cryptography.hazmat.primitives.asymmetric.padding.OAEP(
            mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None))
        print("Innermost cell with keys (Encrypted)")
        print(sendingCell)
        sendingCell = cell( sendingCell, Type="relay connect")  # connection type. exit node always knows
        sendingCell.ip = gonnect
        sendingCell.port = gonnectport  # save the stuff i should be sending over.
        IV = os.urandom(16)
        cipher = Cipher(algorithms.AES(list_of_Servers_between[1].key), modes.CBC(IV),
                        backend=default_backend())  # 256 bit length cipher lel
        encryptor = cipher.encryptor()  # encrypt the entire cell
        encrypted = encryptor.update(self.padder128(pickle.dumps(sendingCell)))
        encrypted += encryptor.finalize()  # finalise encryption.
        sendingCell = cell(encrypted, IV=IV, Type="relay connect")
        sendingCell.ip = list_of_Servers_between[1].ip
        sendingCell.port = list_of_Servers_between[1].port
        sendingCell = cell(pickle.dumps(sendingCell),Type="relay")
        IV = os.urandom(16)

        cipher = Cipher(algorithms.AES(list_of_Servers_between[0].key), modes.CBC(IV),
                        backend=default_backend())  # 256 bit length cipher lel
        encryptor = cipher.encryptor()  # encrypt the entire cell
        encrypted = encryptor.update(self.padder128(pickle.dumps(sendingCell)))
        encrypted += encryptor.finalize()  # finalise encryption.
        sendingCell = cell(encrypted, IV=IV, Type="relay")
        sendingCell.ip = list_of_Servers_between[0].ip
        sendingCell.port = list_of_Servers_between[0].port
        try:
            sock = list_of_Servers_between[0].socket
            sock.send(pickle.dumps(sendingCell))  # send over the cell
            theircell = sock.recv(4096)  # await answer
            # you now receive a cell with encrypted payload.
            print(theircell)
            theircell = pickle.loads(theircell)
            print(theircell.payload)
            counter=0
            while (counter < len(list_of_Servers_between)):
                cipher = Cipher(algorithms.AES(list_of_Servers_between[counter].key), modes.CBC(theircell.IV),
                                backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(theircell.payload)
                decrypted += decryptor.finalize()  # finalise decryption
                print(decrypted)
                theircell = pickle.loads(decrypted)
                counter += 1
                theircell = pickle.loads(theircell.payload)
            if (theircell.type == theircell._Types[3]):
                print("FAILED AT CONNECTION!")
                return
            # theircell = pickle.loads(theircell.payload)

            signature = theircell.signature  # this cell isn't encrypted. Extract the signature to verify
            theircell.signature = None
            theirRSA.verify(signature, theircell.salt,
                            cryptography.hazmat.primitives.asymmetric.padding.PSS(
                                mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(hashes.SHA256()),
                                salt_length=cryptography.hazmat.primitives.asymmetric.padding.PSS.MAX_LENGTH),
                            hashes.SHA256())
            # verify that the cell was signed using their key.
            # at this point, you have the cell that is the public key of your target server. Additionally, salt too..
            theirKey = serialization.load_pem_public_key(theircell.payload,
                                                         backend=default_backend())  # load up their key.
            shared_key = ECprivate_key.exchange(ec.ECDH(), theirKey)
            derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=theircell.salt, info=None,
                               backend=default_backend()).derive(shared_key)
            self.serverList.append(Server(gonnect, sock, derived_key, ECprivate_key, theirRSA, gonnectport))
            print("connected successfully to server @ " + gonnect + "   Port: " + str(gonnectport))
        except error:
            print("socketerror")

    def req(self,request, list_of_Servers_between): #send out stuff in router.
        print("REQUEST SENDING TEST")
        # must send IV and a cell that is encrypted with the next public key
        # public key list will have to be accessed in order with list of servers.
        # number between is to know when to stop i guess.
        sendingCell = cell( request,Type = "Req")  # connection type. exit node always knows
        IV = os.urandom(16)
        cipher = Cipher(algorithms.AES(list_of_Servers_between[2].key), modes.CBC(IV),
                        backend=default_backend())  # 256 bit length cipher lel
        encryptor = cipher.encryptor()  # encrypt the entire cell
        encrypted = encryptor.update(self.padder128(pickle.dumps(sendingCell)))
        encrypted += encryptor.finalize()  # finalise encryption.
        sendingCell = cell(encrypted, IV=IV, Type="relay")
        sendingCell.ip = list_of_Servers_between[2].ip
        sendingCell.port = list_of_Servers_between[2].port
        sendingCell = cell(pickle.dumps(sendingCell), Type="relay")


        IV = os.urandom(16)
        cipher = Cipher(algorithms.AES(list_of_Servers_between[1].key), modes.CBC(IV),
                        backend=default_backend())  # 256 bit length cipher lel
        encryptor = cipher.encryptor()  # encrypt the entire cell
        encrypted = encryptor.update(self.padder128(pickle.dumps(sendingCell)))
        encrypted += encryptor.finalize()  # finalise encryption.
        sendingCell = cell(encrypted, IV=IV, Type="relay")
        sendingCell.ip = list_of_Servers_between[1].ip
        sendingCell.port = list_of_Servers_between[1].port
        sendingCell = cell(pickle.dumps(sendingCell), Type="relay")
        IV = os.urandom(16)

        cipher = Cipher(algorithms.AES(list_of_Servers_between[0].key), modes.CBC(IV),
                        backend=default_backend())  # 256 bit length cipher lel
        encryptor = cipher.encryptor()  # encrypt the entire cell
        encrypted = encryptor.update(self.padder128(pickle.dumps(sendingCell)))
        encrypted += encryptor.finalize()  # finalise encryption.
        sendingCell = cell(encrypted, IV=IV, Type="relay")
        sendingCell.ip = list_of_Servers_between[0].ip
        sendingCell.port = list_of_Servers_between[0].port
        try:
            sock = list_of_Servers_between[0].socket
            sock.send(pickle.dumps(sendingCell))  # send over the cell
            theircell = sock.recv(32768)  # await answer
            # you now receive a cell with encrypted payload.
            print("received cell")
            print(len(theircell))
            print(theircell)
            theircell = pickle.loads(theircell)
            print("received cell payload")
            print(theircell.payload)
            counter = 0
            while (counter < len(list_of_Servers_between)):
                cipher = Cipher(algorithms.AES(list_of_Servers_between[counter].key), modes.CBC(theircell.IV),
                                backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(theircell.payload)
                decrypted += decryptor.finalize()  # finalise decryption
                theircell = pickle.loads(decrypted)
                counter += 1
                if(counter<len(list_of_Servers_between)):
                    theircell = pickle.loads(theircell.payload)

            if (theircell.type == theircell._Types[3]):
                print("FAILED AT CONNECTION!")
                return
            # theircell = pickle.loads(theircell.payload)
            response = pickle.loads(theircell.payload)
            print(response.content)
            print("questionably succeeded....\n\n")
            return response
        except error:
            print("socketerror")


me = Client()
funcs={"a":me.firstConnect, "b": me.moreConnect1, "c": me.moreConnect2, "d":me.req} #add more methods here.
while(True):
    target = input(" 'a' for adding first connection. arguments are: '<IP> <PORT> <IDENTITY>'\n" +
                   " 'b' for adding second connection. arguments are: '<IP> <PORT> <IDENTITY>'\n" +
                   " 'c' for adding third connection. arguments are: '<IP> <PORT> <IDENTITY>'\n" +
                   " 'd' for adding testing the connection to the last node. arguments are: '<type of request>, <request>'\n"
                   + " If you want localhost, type 'LOCAL' \n"
                   )
    arguments = input("Now tell me what you want to use as an argument if any. split by spaces. else just press enter.\n")
    listofstuff = arguments.split()
    if(target in funcs.keys()):
        if (listofstuff[0] == "LOCAL"):
            listofstuff[0] = gethostbyname(gethostname())
        if(target=="a"):
            listofstuff[1]=int(listofstuff[1])
            print(listofstuff[0])
            print(listofstuff[1])
            print(listofstuff[2])
            listofstuff[2]=int(listofstuff[2])
            tempopen = open("publics/publictest" + str(listofstuff[2]) + ".pem", "rb")
            publickey = serialization.load_pem_public_key(tempopen.read(),backend=default_backend())  # used for signing, etc.
            funcs[target](listofstuff[0],listofstuff[1],publickey) #arguments should only be the ip address..
            tempopen.close()
        if (target == "b"):
            listofstuff[1] = int(listofstuff[1])
            print(listofstuff[0])
            print(listofstuff[1])
            print(listofstuff[2])
            listofstuff[2] = int(listofstuff[2])
            tempopen = open("publics/publictest" + str(listofstuff[2]) + ".pem", "rb")
            publickey = serialization.load_pem_public_key(tempopen.read(),
                                                          backend=default_backend())  # used for signing, etc.
            funcs[target](listofstuff[0], listofstuff[1],me.serverList, publickey)  # arguments should only be the ip address..
        if (target == "c"):
            listofstuff[1] = int(listofstuff[1])
            print(listofstuff[0])
            print(listofstuff[1])
            print(listofstuff[2])
            listofstuff[2] = int(listofstuff[2])
            tempopen = open("publics/publictest" + str(listofstuff[2]) + ".pem", "rb")
            publickey = serialization.load_pem_public_key(tempopen.read(),
                                                          backend=default_backend())  # used for signing, etc.
            funcs[target](listofstuff[0], listofstuff[1],me.serverList, publickey)  # arguments should only be the ip address..
        if(target=="d"):
            funcs[target](listofstuff[0],me.serverList) #request test


"""
tempopen = open("publics/publictest" + "0"+ ".pem", "rb")
publickey = serialization.load_pem_public_key(tempopen.read(),backend=default_backend())  # used for signing, etc.
tempopen.close()
print("\n\n\n\n")
me.firstConnect(gethostbyname(gethostname()), 45000,publickey)
tempopen = open("publics/publictest" + "1"+ ".pem", "rb")
publickey = serialization.load_pem_public_key(tempopen.read(),backend=default_backend())  # used for signing, etc.
tempopen.close()
print("\n\n\n\n")
me.moreConnect1(gethostbyname(gethostname()),45001,me.serverList,publickey)
tempopen = open("publics/publictest" + "2"+ ".pem", "rb")
publickey = serialization.load_pem_public_key(tempopen.read(),backend=default_backend())  # used for signing, etc.
tempopen.close()
print("\n\n\n\n")
me.moreConnect2(gethostbyname(gethostname()),45002,me.serverList,publickey)
me.req("test req type","test req",me.serverList)
"""
