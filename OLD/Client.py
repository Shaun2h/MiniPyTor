#from cryptography.hazmat.primitives import serialization
#only use above if you want to save your pem... but it should NOT be required.

from socket import *
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import threading #for testing purposes.
import os
import netifaces
from struct import *
from random import shuffle
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


#operation requires the knowledge of the server's IP



myIP=[]

for i in netifaces.interfaces(): # looking at your interfaces
    a=netifaces.ifaddresses(i)
    print(a)
    if(netifaces.AF_INET in a.keys()): # Using AF_INET addresses..
        list_of_ip =a[netifaces.AF_INET]
        for k in list_of_ip:
            myIP.append(k["addr"])
print(myIP) # this is where you broadcast on all networks available to find a server... not used for now.

#I couldn't use UDP because i wouldn't be able to track who's what without some form of ID at the end and start nodes. so it's TCP all the way.
#print(netifaces.AF_INET)
class Server():
    def __init__(self,ip,socket,derivedkey,theirpublickey):
        self.ip = ip
        self.socket =  socket
        self.key = derivedkey
        self.theirpublickey = theirpublickey





class Client():
    serverList=[]
    def __init__(self,IP):

        # generate public private key pair
        self.myIP = IP # a string with your IP
        a = IP
        while(len(a)<32):
            a+=" "
        self.IP32= a #a 32 bytes IP
        #self.private_key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=3072) #RSA
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend()) #elliptic curve
        self.public_key = self.private_key.public_key()
        self.serialised_public_key = self.public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        #serialised public key has a length of 215
    # serialised version for sending

    def Gonnection(self,gonnect):
        #gonnection is called to initiate any connection with any server. relies of course on you having the server ips already.
        #port is defaulted to 45000.
        #this simply enables you to save the servers that we should approach.
        #THIS IS NOT FOR REQUESTS.
        #for i in (debuglist):#broadcastTargets):
        flag = False
        """for i in self.serverList:
            if (i.ip == gonnect):
                flag = True
        """
        if (flag):
            print("You've connected to this IP which acts as a server already.")
            return
        sock= socket(AF_INET, SOCK_STREAM) #your connection is TCP.

        try:
            #sock.connect((gonnect,45000))
            sock.connect(('192.168.1.137', 45000))
            # signature = self.private_key.sign(self.serialised_public_key,ec.ECDSA(hashes.SHA256()))  # sign with private key
            # theirkey.verify(theirsignature, theirkey, ec.ECDSA(hashes.SHA256()))

            sock.send(self.serialised_public_key)# send my public key... tcp style
            theirkey= sock.recv(4096)
            theirkey = serialization.load_pem_public_key(theirkey, backend=default_backend())
            shared_key = self.private_key.exchange(ec.ECDH(), theirkey)
            randominfo = sock.recv(4096)  # randomised iv for derived key that is shared
            derived_key = HKDF(algorithm = hashes.SHA256(),length = 32,salt = None,info = randominfo,backend = default_backend()).derive(shared_key)
            sock.send(bytes(1)) #send a quick signal
            their_RSA_key = sock.recv(4096)
            their_RSA_key = serialization.load_pem_public_key(their_RSA_key, backend=default_backend()) #this is the public key of the server.

            #cipher = Cipher(algorithms.AES(derived_key), modes.CBC(), backend=default_backend())
            #encryptor = cipher.encryptor()
            #ct = encryptor.update(b"a secret message") + encryptor.finalize()
            #decryptor = cipher.decryptor()
            #decryptor.update(ct) + decryptor.finalize()
            self.serverList.append(Server(gonnect,sock, derived_key,their_RSA_key))
            print("connected successfully to server @ " + gonnect)

        except error:
            print("disconnected or server is not online/ connection was refused.")


    def req(self,typeofreq,request): #send out stuff in router.

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
                """print("firstdata")
                print(firstdata)
                print("firstdatalen")
                print(len(firstdata))"""
                #signature = self.private_key.sign(firstdata,ec.ECDSA(hashes.SHA256()))  # sign with private key
                padder2 = padding.PKCS7(256).padder()  # pad to 256 BITS ie 32 bytes for ip address....
                p2 = padder2.update(str.encode(ip2)) #pad ip
                p2 += padder2.finalize() #finalize.
                """print("padded ip2")
                print(p2)"""
                seconddata = key2.encrypt(firstdata, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None))
                #seconddata+=iv2+p2
                seconddata += p2 #append ip
                """print("seconddata")
                print(seconddata)
                print("seconddata len")
                print(len(seconddata))"""
                """padder2 = padding.PKCS7(256).padder()  # same thing
                p3 = padder2.update(str.encode(ip3))
                p3 += padder2.finalize()
                """
                thirddata = key3.encrypt(seconddata, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None)) #don't append IP.
                #thirddata+=iv3+p3
                """print("ip3 len")
                print(len(p3))
                print("thirddata len")
                print(len(thirddata))
                print("thirddata")
                print(thirddata)
                print("ip")
                print(p3)"""

                cipher = Cipher(algorithms.AES(key1), modes.CBC(iv3), backend=default_backend())
                socket3.send(thirddata+iv3) #send data
                socket3.recv(4096) #get info



            #stuff





    #print(serialised_public_key.splitlines()==serialization.load_pem_public_key(serialised_public_key,backend=default_backend()).public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).splitlines())




me = Client(myIP[0])
funcs={"a":me.Gonnection,"c":me.req} #add more methods here.
while(True):
    target = input(" 'a' for adding more connections. \n 'c' for attempting to obtain some webpage. \n keep in mind that if you haven't connected to at least 3 servers, YOU CANNOT CONNECT TO A WEBPAGE. Requires IP address argument\n will print out webpage.\n")
    arguments = input("okay. Now tell me what you want to use as an argument if any. else just press enter.\n")
    if(target in funcs.keys()):
        #if(arguments==""):
            #funcs[target]()
    #else:
        if(target=="a"):
            funcs[target](arguments) #arguments should only be the ip address..
        if(target=="c"):
            req_type = input("REQUEST TYPE PLEASE\n")
            if(req_type=="get" or req_type=="GET"):
                funcs[target](1,arguments)  # argument is of course your url to request.
            if (req_type == "POST" or req_type == "POST"):
                funcs[target](2,arguments)  # argument is of course your url to request.
            if (req_type == "put" or req_type == "PUT"):
                funcs[target](3,arguments) #argument is of course your url to request.










