from socket import *
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import requests
from struct import *
from random import randint
import os
import select

class client():
    def __init__(self,sock,key,generatedKey,theirpublickey):
        self.socket = sock
        self.key = key # the derived key
        self.generatedKey= generatedKey #the generated elliptic curve diffie hellman key.
        self.theirpublickey = theirpublickey
        #save their public key here..
class Server():
    CLIENTS=[]
    CLIENTSOCKS=[]
    def __init__(self):
        self.TRUEprivate_key = rsa.generate_private_key(backend=default_backend(),public_exponent=65537, key_size=2048)
        self.sendingpublickey = self.TRUEprivate_key.public_key() #public key for sending out.
        self.serversocket= socket(AF_INET,SOCK_STREAM) #tcp type chosen for first.
        self.serversocket.bind(("",45000)) #better be "" or it'll listen only on localhost
        self.serversocket.listen(100)
        
    def main(self):
        clientclass=None #initialise as none.
        readready,_,_ = select.select([self.serversocket]+self.CLIENTSOCKS,[],[])
        for i in readready:
            print("some")
            if(i==self.serversocket): #i've gotten a new connection
                print("client get")
                (clientsocket, address) = self.serversocket.accept()
                try:
                    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())  # elliptic curve
                    public_key = private_key.public_key()  # duh same.
                    serialised_public_key = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
                    theirkey= clientsocket.recv(4096) #obtain their public key
                    theirpublickey = serialization.load_pem_public_key(theirkey, backend=default_backend())  # .public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                    clientsocket.send(serialised_public_key)  # pass them the generated public key data, and my signature.
                    shared_key = private_key.exchange(ec.ECDH(), theirpublickey)
                    salty= str.encode(str(randint(0, 99999999)))  # randomised IV
                    clientsocket.send(salty)  # send them my randomised iv
                    derived_key = HKDF(algorithm = hashes.SHA256(),length = 32,salt = None,info =salty ,backend = default_backend()).derive(shared_key)

                    #derived key is there to ensure that i know it's coming from THEM.
                    #protects man in the middle.

                    #RSA Encryption time..
                    clientsocket.recv(4096) #await signal

                    #cipher = Cipher(algorithms.AES(derived_key), modes.CBC(), backend=default_backend())
                    #encryptor = cipher.encryptor()
                    #ct = encryptor.update(b"a secret message") + encryptor.finalize()
                    #decryptor = cipher.decryptor()
                    #decryptor.update(ct) + decryptor.finalize()

                    clientclass=client(clientsocket,derived_key,private_key,theirpublickey)#cipher)
                    self.CLIENTS.append(clientclass)
                    self.CLIENTSOCKS.append(clientsocket)
                    print("COMPLETEDCOMPLETEDCOMPLETED")
                except error:
                    if(clientclass!=None):
                        self.CLIENTS.remove(clientclass) #remove the object. i'm not sure how the error would have been thrown out at this point though. probably useless..
                        print("disconnected")

            else:
                try:
                    received = i.recv(4096)
                except error:
                    continue
                if(len(received)==0):
                    print("CLIENT WAS CLOSED!")
                    for k in self.CLIENTS:
                        if(k.socket==i):
                            clienttoremove=k
                    self.CLIENTSOCKS.remove(i)
                    self.CLIENTS.remove(clienttoremove)
                else:
                    #redirect
                    """print("total received length")
                    print(len(received))
                    print(received)"""
                    #iv = received[-48:-32] #before last 32 is iv
                    #ip = received[-32:] #last 32 elements
                    iv = received[-16:] #last 16 bits are now the iv.
                    everythingelse=received[:-16]
                    print("length of encrypted")
                    print(len(everythingelse))
                    print("encrypted")
                    print(everythingelse)
                    """print("length of ip bytes (they refer to me though..)")
                    print(len(ip))
                    print("ip bytes (my ip, in byte form. duh.)")
                    print(ip)"""
                    """print("length of iv bytes")
                    print(len(iv))
                    print("iv bytes")
                    print(iv)"""
                    clientwhosent=None
                    for k in self.CLIENTS:
                        if (k.socket == i):
                            clientwhosent = k
                    if(clientwhosent==None):
                        continue #was a spoofed packet
                    try:
                        cipher= Cipher(algorithms.AES(clientwhosent.key), modes.CBC(iv), backend=default_backend())
                        AESdecryptor = cipher.decryptor()
                        decrypted = AESdecryptor.update(everythingelse)
                        decrypted += AESdecryptor.finalize()
                        unpadder = padding.PKCS7(256).unpadder() #IP is padded to 256
                        decrypted = self.TRUEprivate_key.decrypt(decrypted,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
                        print("len decrypted "+str(len(decrypted)))
                        print("decrypted bytes")
                        print(decrypted)
                        u = unpadder.update(decrypted[-32:]) #ATTEMPT TO STRIP THE IP AT THE LAST 32 BITS
                        u += unpadder.finalize()
                        print("I AM NOT THE LAST HOP.")
                        print(str(u))
                        print("length of bytes of next hop bytes " + str(len(u)))
                        print("bytes of next hop")
                        print(u)
                        print("target of next hop")
                        print(str(u))  # this is the next ip hop.
                        #send decrypted[:-32] i.e. without the ip address. Ensure it is wrapped in a AES with the next server. don't forget to include iv.
                        i.send("h")
                        for k in self.CLIENTS:
                            if (k.socket == i):
                                clienttoremove = k
                        self.CLIENTSOCKS.remove(i)
                        self.CLIENTS.remove(clienttoremove) #close the connection and kick them out.
                        i.close() #now close and leave.
                        self.BounceToOtherServer(str(u),decrypted[:-32]) #without the IP Address.
                    except ValueError:
                        print("AM THE LAST ONE! AM THE LAST ONE!")
                        IPofSender = str(decrypted)[-247:-215]
                        originalPEM = str(decrypted)[-215:]
                        print("requesting"+str(decrypted)[:-32])
                        sendback = requests.get(decrypted) #obtained the data
                        originalpublickey = serialization.load_pem_public_key(IPofSender,password = None,backend = default_backend()) #load pem public key here.
                        #now do the same thing as a client and select 3 things to send...
                        #no other padding is required.
                        #DO SOMETHING WITH THE DATA





    def BounceToOtherServer(self,targetIP,data_to_send):
        #data to send must be bytes form.
        #target ip is a string form. not the byte form!
        sock = socket(AF_INET, SOCK_STREAM)  # your connection is TCP.
        Ephermeral_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())  # elliptic curve
        Ephermeral_public_key = Ephermeral_private_key.public_key()
        Ephermeral_serialised_public_key = Ephermeral_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)
        try:
            sock.connect((targetIP, 45000))
            sock.send(Ephermeral_serialised_public_key)  # send my public key... tcp style
            theirkey = sock.recv(4096)
            theirkey = serialization.load_pem_public_key(theirkey, backend=default_backend())
            shared_key = Ephermeral_private_key.exchange(ec.ECDH(), theirkey)
            randominfo = sock.recv(4096)  # randomised iv for derived key that is shared
            derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=randominfo,
                               backend=default_backend()).derive(shared_key)
            print("connected successfully to server @ " + targetIP+"  Now sending data...")
            IV = os.urandom(32)
            Connection_cipher = Cipher(algorithms.AES(derived_key), modes.CBC(IV), backend=default_backend())

            ct = Connection_cipher.encryptor().update(data_to_send)
            ct+= Connection_cipher.finalize() #AES ENCRYPTION of what i need to send.
            ct+=IV #append the IV to the thing i wish to send.
            sock.send(ct) #send them the data. await.
            sock.recv(4096) #wait for signal
            sock.close() #close it.




        except error:
            print("disconnected or server is not online/ connection was refused.")




server = Server()
while True:
    server.main()
