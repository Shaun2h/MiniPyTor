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
import threading #for testing purposes.
import os
import netifaces
import pickle
import enum
from struct import *
from random import shuffle
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class cell():
    _Types = ["AddCon", "Req", "Resp"]

    def __init__(self, isconnection, isreq, payload, IV=None, salt=None, signature=None):
        if (isconnection):
            self.type = self._Types[0]  # is a connection request. so essentially some key is being pushed out here.
        else:
            if (isreq):
                self.type = self._Types[1]  # is a request.
            else:
                self.type = self._Types[2]
        if (self.type == self._Types[1]):
            self.payload = payload
        else:  # is a connection request or response...
            if (self.type == self._Types[2]):  # is a response. Requires a signature.
                self.signature = signature
            self.payload = payload  # in this case, it should contain some public key in byte form.
            self.IV = IV  # save the IV since it's a connection cell.
            if (salt != None):
                self.salt = salt


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

    def Gonnection(self,gonnect1,gonnectport1,gonnect2,gonnectport2,gonnect3,gonnectport3):
        #begin a connection between different servers.
        self.firstConnect(gonnect1,gonnectport1)

    def makeFirstConnectCell(self):
        ECprivate_key = ec.generate_private_key(ec.SECP384R1(), default_backend())  # elliptic curve
        DHpublicKeyBytes = ECprivate_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)
        sendingCell = cell(True, False, DHpublicKeyBytes, None, None,
                           None)  # send the initialising cell, by sending the DHpublicKeyBytes
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
            readiedcell = self.padder128(pickle.dumps(sendingCell))
            encryptedCell = theirRSApublic.encrypt(readiedcell,cryptography.hazmat.primitives.asymmetric.padding.OAEP(
                mgf = cryptography.hazmat.primitives.asymmetric.padding.MGF1(algorithm=hashes.SHA256()),algorithm = hashes.SHA256(),label = None))


            sock.send(encryptedCell)  # send my public key... tcp style
            theircell= sock.recv(4096)
            theircell = pickle.loads(theircell) #load up their cell
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

    def moreConnect(self,gonnect,gonnectport,list_of_Servers_between,theirRSA):
        #must send IV and a cell that is encrypted with the next public key
        #public key list will have to be accessed in order with list of servers.
        #number between is to know when to stop i guess.
        sendingCell, ECprivate_key = self.makeFirstConnectCell()
        sendingCell.ip = gonnect
        sendingCell.port = gonnectport #save the stuff i should be sending over.
        for i in list_of_Servers_between: #continuously loop through the servers
            IV = os.urandom(16)
            cipher = Cipher(algorithms.AES(i.key), modes.CBC(IV),backend=default_backend())  # 256 bit length cipher lel
            encryptor = cipher.encryptor() #encrypt the entire cell
            encrypted = encryptor.update(pickle.dumps(sendingCell))
            encrypted+= encryptor.finalize() #finalise encryption.
            sendingCell = cell(True,False,encrypted,IV)  #dump encrypted into another cell.
            sendingCell.ip = i.ip  # update the port and IP into the outer layer.
            sendingCell.port = i.port
        final_sendingCell = pickle.dumps(sendingCell)
        try:
            sock = socket(AF_INET, SOCK_STREAM)  # your connection is TCP.
            sock.connect((sendingCell.ip, sendingCell.port))
            sock.send(final_sendingCell)  # send over the cell
            theircell = sock.recv(4096) # await answer
            #you now receive a cell with encrypted payload.
            theircell = pickle.loads(theircell)
            counter =len(list_of_Servers_between)-1

            while(counter>=0):
                cipher = Cipher(algorithms.AES(list_of_Servers_between[counter].key),modes.CBC(theircell.IV),backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(theircell.payload)
                decrypted = decryptor.finalize() #finalise decryption
                theircell = pickle.loads(decrypted)
                counter-=1
            signature = theircell.signature  # this cell isn't encrypted. Extract the signature to verify
            theircell.signature = None
            ###SIG VERIFY HERE
            ###
            ###
            ###

            # at this point, you have the cell that is the public key of your target server. Additionally, salt too..
            theirKey = serialization.load_pem_public_key(theircell.payload,backend=default_backend())  # load up their key.
            shared_key = self.private_key.exchange(ec.ECDH(), theirKey)
            derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=theircell.salt, info=None,backend=default_backend()).derive(shared_key)

        except error:
            return None




    def req(self,typeofreq,request): #send out stuff in router.
        pass

me = Client()
funcs={"a":me.firstConnect} #add more methods here.
while(True):
    target = input(" 'a' for adding more connections. arguments are: '<IP> <PORT> <IDENTITY>'\n")
    arguments = input("okay. Now tell me what you want to use as an argument if any. else just press enter.\n")
    listofstuff = arguments.split()
    if(target in funcs.keys()):
        if(target=="a"):
            listofstuff[1]=int(listofstuff[1])
            print(listofstuff[0])
            print(listofstuff[1])
            print(listofstuff[2])
            listofstuff[2]=int(listofstuff[2])
            tempopen = open("publics/publictest" + str(listofstuff[2]) + ".pem", "rb")
            publickey = serialization.load_pem_public_key(tempopen.read(),backend=default_backend())  # used for signing, etc.
            funcs[target](listofstuff[0],listofstuff[1],publickey) #arguments should only be the ip address..


    # signature = self.private_key.sign(self.serialised_public_key,ec.ECDSA(hashes.SHA256()))  # sign with private key
    # theirkey.verify(theirsignature, theirkey, ec.ECDSA(hashes.SHA256()))
"""
        if(len(self.serverList)<3): #you need 3 to do stuff
            print("Can't do that. Less then 3 routers.")
            return
        else:
            if(typeofreq==1):
                shuffle(self.serverList) #shuffle serverList
                #send to server 3, which bounces it to 2 , 1 and target.
                socket3 = self.serverList[2].socket
                #first hop
                ip1 = self.serverList[0].ip
                key1 = self.serverList[0].theirpublickey #grab all key and ip required #RSA KEY
                #iv1 = os.urandom(16) #iv is random.
                ip2 = self.serverList[1].ip
                #iv2 = os.urandom(16)
                key2 = self.serverList[0].theirpublickey #RSA KEY
                ip3 = self.serverList[2].ip
                iv3 = os.urandom(16)
                key3 = self.serverList[0].theirpublickey #RSA KEY
                firstdata= key1.encrypt(str.encode(request+self.IP32+self.serialised_public_key),padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA256()),algorithm = hashes.SHA256(),label = None))
                padder1b = padding.PKCS7(256).padder()  # pad ip to 256 bits... because this can vary too...
                p1b = padder1b.update(str.encode(ip1))
                p1b += padder1b.finalize()
                #firstdata+=iv1+p1b #place the iv and ip here.
                firstdata += + p1b  # place only here.
                ##print("firstdata")
                ##print(firstdata)
                ##print("firstdatalen")
                ##print(len(firstdata))
                #signature = self.private_key.sign(firstdata,ec.ECDSA(hashes.SHA256()))  # sign with private key
                padder2 = padding.PKCS7(256).padder()  # pad to 256 BITS ie 32 bytes for ip address....
                p2 = padder2.update(str.encode(ip2)) #pad ip
                p2 += padder2.finalize() #finalize.
                ##print("padded ip2")
                ##print(p2)
                seconddata = key2.encrypt(firstdata, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None))
                #seconddata+=iv2+p2
                seconddata += p2 #append ip
                ##print("seconddata")
                ##print(seconddata)
                ##print("seconddata len")
                ##print(len(seconddata))
                ##padder2 = padding.PKCS7(256).padder()  # same thing
                ##p3 = padder2.update(str.encode(ip3))
                ##p3 += padder2.finalize()
                
                thirddata = key3.encrypt(seconddata, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None)) #don't append IP.
                #thirddata+=iv3+p3
                ##print("ip3 len")
                ##print(len(p3))
                ##print("thirddata len")
                ##print(len(thirddata))
                ##print("thirddata")
                ##print(thirddata)
                ##print("ip")
                ##print(p3)

                ##cipher = Cipher(algorithms.AES(key1), modes.CBC(iv3), backend=default_backend())
                ##socket3.send(thirddata+iv3) #send data
                ##socket3.recv(4096) #get info
"""
"192.168.1.116 45000 0"
