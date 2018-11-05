"""Client class file"""

import pickle
import os
import json
import sys
import requests

from struct import *
from socket import *

import cryptography.hazmat.primitives.asymmetric.padding
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from util import padder128
from celldef import cell


class Server():
    """Server class"""

    def __init__(self, ip, socket, derived_key, EC_key, RSA_key, port):
        self.ip = ip
        self.socket = socket
        self.key = derived_key
        self.EC_key = EC_key
        self.RSA_key = RSA_key
        self.port = port


class Client():
    """Client class"""
    serverList = []

    def __init__(self):

        # generate public private key pair
        self.private_key = rsa.generate_private_key(
            backend=default_backend(), public_exponent=65537, key_size=3072)  # RSA
        self.public_key = self.private_key.public_key()
        self.serialised_public_key = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        # serialised RSA public key.

    def makeFirstConnectCell(self):
        """add method def"""
        ECprivate_key = ec.generate_private_key(
            ec.SECP384R1(), default_backend())  # elliptic curve
        DHpublicKeyBytes = ECprivate_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)
        # send the initialising cell, by sending the DHpublicKeyBytes
        sendingCell = cell(DHpublicKeyBytes, Type="AddCon")
        return sendingCell, ECprivate_key

    def firstConnect(self, gonnect, gonnectport, RSA_keypublic):
        """you should already HAVE their public key."""
        try:
            sock = socket(AF_INET, SOCK_STREAM)  # your connection is TCP.
            sock.connect((gonnect, gonnectport))
            sendingCell, ECprivate_key = self.makeFirstConnectCell()
            # key encryption for RSA HERE USING SOME PUBLIC KEY
            readiedcell = pickle.dumps(sendingCell)
            #print("first connect Actual cell (encrypted bytes) ")
            # print(readiedcell)
            encryptedCell = RSA_keypublic.encrypt(readiedcell, cryptography.hazmat.primitives.asymmetric.padding.OAEP(
                mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            #print("first connect Actual cell(decrypted bytes)")
            # print(encryptedCell)
            sock.send(encryptedCell)  # send my public key... tcp style
            their_cell = sock.recv(4096)
            their_cell = pickle.loads(their_cell)  # load up their cell
            # print(their_cell.type)
            # this cell isn't encrypted. Extract the signature to verify
            signature = their_cell.signature
            try:
                RSA_keypublic.verify(signature, their_cell.salt,
                                     cryptography.hazmat.primitives.asymmetric.padding.PSS(
                                         mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(
                                             hashes.SHA256()),
                                         salt_length=cryptography.hazmat.primitives.asymmetric.padding.PSS.MAX_LENGTH), hashes.SHA256())
                # verify that the cell was signed using their key.
                # load up their key.
                theirKey = serialization.load_pem_public_key(
                    their_cell.payload, backend=default_backend())

                shared_key = ECprivate_key.exchange(ec.ECDH(), theirKey)
                derived_key = HKDF(algorithm=hashes.SHA256(
                ), length=32, salt=their_cell.salt, info=None, backend=default_backend()).derive(shared_key)
                # cipher = Cipher(algorithms.AES(derived_key), modes.CBC(IV), backend=default_backend()) #256 bit length cipher lel
                #encryptor = cipher.encryptor()
                #ct = encryptor.update() + encryptor.finalize()
                # decryptor = cipher.decryptor()
                # decryptor.update(ct) + decryptor.finalize()

                # Connection is established at this point.

                #print("connected successfully to server @ " + gonnect + "   Port: " + str(gonnectport))
                self.serverList.append(
                    Server(gonnect, sock, derived_key, ECprivate_key, RSA_keypublic, gonnectport))
                return   # a server item is created.

            except InvalidSignature:
                #print("Something went wrong.. Signature was invalid.")
                return None

        except (error, ConnectionResetError, ConnectionRefusedError)as e:
            print("disconnected or server is not online/ connection was refused.")

    def moreConnect1(self, gonnect, gonnectport, intermediate_servers, RSA_key):
        """must send IV and a cell that is encrypted with the next public key
        public key list will have to be accessed in order with list of servers.
        number between is to know when to stop i guess."""

        sendingCell, ECprivate_key = self.makeFirstConnectCell()
        sendingCell = pickle.dumps(sendingCell)
        #print("Innermost cell with keys")
        # print(sendingCell)
        sendingCell = RSA_key.encrypt(sendingCell, cryptography.hazmat.primitives.asymmetric.padding.OAEP(
            mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(
                algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None))
        #print("Innermost cell with keys (Encrypted)")
        # print(sendingCell)
        # connection type. exit node always knows
        sendingCell = cell(sendingCell, Type="relay connect")
        sendingCell.ip = gonnect
        # save the stuff i should be sending over.
        sendingCell.port = gonnectport
        IV = os.urandom(16)

        cipher = Cipher(algorithms.AES(intermediate_servers[0].key), modes.CBC(
            IV), backend=default_backend())  # 256 bit length cipher lel
        encryptor = cipher.encryptor()  # encrypt the entire cell
        encrypted = encryptor.update(padder128(pickle.dumps(sendingCell)))
        encrypted += encryptor.finalize()  # finalise encryption.
        sendingCell = cell(encrypted, IV=IV, Type="relay connect")

        try:
            sock = intermediate_servers[0].socket
            sock.send(pickle.dumps(sendingCell))  # send over the cell
            #print("cell sent: ")
            # print(pickle.dumps(sendingCell))
            their_cell = sock.recv(4096)  # await answer
            # you now receive a cell with encrypted payload.
            counter = len(intermediate_servers)-1
            their_cell = pickle.loads(their_cell)
            while(counter >= 0):
                cipher = Cipher(algorithms.AES(intermediate_servers[counter].key), modes.CBC(
                    their_cell.IV), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(their_cell.payload)
                decrypted += decryptor.finalize()  # finalise decryption
                # print(decrypted)
                their_cell = pickle.loads(decrypted)
                counter -= 1
                # print(their_cell.payload)
                their_cell = pickle.loads(their_cell.payload)
            if (their_cell.type == their_cell._Types[3]):
                #print("FAILED AT CONNECTION!")
                if (their_cell.payload == "CONNECTIONREFUSED"):
                    print("Connection was refused. Is the server online yet?")
                return
            #their_cell = pickle.loads(their_cell.payload)

            # this cell isn't encrypted. Extract the signature to verify
            signature = their_cell.signature
            their_cell.signature = None
            RSA_key.verify(signature, their_cell.salt,
                           cryptography.hazmat.primitives.asymmetric.padding.PSS(
                               mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(
                                   hashes.SHA256()),
                               salt_length=cryptography.hazmat.primitives.asymmetric.padding.PSS.MAX_LENGTH),
                           hashes.SHA256())
            # verify that the cell was signed using their key.
            # at this point, you have the cell that is the public key of your target server. Additionally, salt too..
            # load up their key.
            theirKey = serialization.load_pem_public_key(
                their_cell.payload, backend=default_backend())
            shared_key = ECprivate_key.exchange(ec.ECDH(), theirKey)
            derived_key = HKDF(algorithm=hashes.SHA256(
            ), length=32, salt=their_cell.salt, info=None, backend=default_backend()).derive(shared_key)
            self.serverList.append(
                Server(gonnect, sock, derived_key, ECprivate_key, RSA_key, gonnectport))
            #print("connected successfully to server @ " + gonnect + "   Port: " + str(gonnectport))
        except (ConnectionResetError, ConnectionRefusedError, error):
            #print("Socket Error, removing from the list.")
            del self.serverList[0]  # remove it from the lsit
            #print("REMOVED SERVER 0 DUE TO FAILED CONNECTION")

    def moreConnect2(self, gonnect, gonnectport, intermediate_servers, RSA_key):
        """must send IV and a cell that is encrypted with the next public key
        public key list will have to be accessed in order with list of servers.
        number between is to know when to stop i guess."""

        sendingCell, ECprivate_key = self.makeFirstConnectCell()
        sendingCell = pickle.dumps(sendingCell)
        #print("Innermost cell with keys")
        # print(sendingCell)
        sendingCell = RSA_key.encrypt(sendingCell, cryptography.hazmat.primitives.asymmetric.padding.OAEP(
            mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(
                algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None))
        #print("Innermost cell with keys (Encrypted)")
        # print(sendingCell)
        # connection type. exit node always knows
        sendingCell = cell(sendingCell, Type="relay connect")
        sendingCell.ip = gonnect
        # save the stuff i should be sending over.
        sendingCell.port = gonnectport
        IV = os.urandom(16)
        cipher = Cipher(algorithms.AES(intermediate_servers[1].key), modes.CBC(IV),
                        backend=default_backend())  # 256 bit length cipher lel
        encryptor = cipher.encryptor()  # encrypt the entire cell
        encrypted = encryptor.update(padder128(pickle.dumps(sendingCell)))
        encrypted += encryptor.finalize()  # finalise encryption.
        sendingCell = cell(encrypted, IV=IV, Type="relay connect")
        sendingCell.ip = intermediate_servers[1].ip
        sendingCell.port = intermediate_servers[1].port
        sendingCell = cell(pickle.dumps(sendingCell), Type="relay")
        IV = os.urandom(16)

        cipher = Cipher(algorithms.AES(intermediate_servers[0].key), modes.CBC(IV),
                        backend=default_backend())  # 256 bit length cipher lel
        encryptor = cipher.encryptor()  # encrypt the entire cell
        encrypted = encryptor.update(padder128(pickle.dumps(sendingCell)))
        encrypted += encryptor.finalize()  # finalise encryption.
        sendingCell = cell(encrypted, IV=IV, Type="relay")
        sendingCell.ip = intermediate_servers[0].ip
        sendingCell.port = intermediate_servers[0].port
        try:
            sock = intermediate_servers[0].socket
            sock.send(pickle.dumps(sendingCell))  # send over the cell
            their_cell = sock.recv(4096)  # await answer
            # you now receive a cell with encrypted payload.
            # print(their_cell)
            their_cell = pickle.loads(their_cell)
            # print(their_cell.payload)
            counter = 0
            while (counter < len(intermediate_servers)):
                cipher = Cipher(algorithms.AES(intermediate_servers[counter].key), modes.CBC(their_cell.IV),
                                backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(their_cell.payload)
                decrypted += decryptor.finalize()  # finalise decryption
                # print(decrypted)
                their_cell = pickle.loads(decrypted)
                counter += 1
                their_cell = pickle.loads(their_cell.payload)
            if (their_cell.type == their_cell._Types[3]):
                #print("FAILED AT CONNECTION!")
                return
            # their_cell = pickle.loads(their_cell.payload)

            # this cell isn't encrypted. Extract the signature to verify
            signature = their_cell.signature
            their_cell.signature = None
            RSA_key.verify(signature, their_cell.salt,
                           cryptography.hazmat.primitives.asymmetric.padding.PSS(
                               mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(
                                   hashes.SHA256()),
                               salt_length=cryptography.hazmat.primitives.asymmetric.padding.PSS.MAX_LENGTH),
                           hashes.SHA256())
            # verify that the cell was signed using their key.
            # at this point, you have the cell that is the public key of your target server. Additionally, salt too..
            theirKey = serialization.load_pem_public_key(their_cell.payload,
                                                         backend=default_backend())  # load up their key.
            shared_key = ECprivate_key.exchange(ec.ECDH(), theirKey)
            derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=their_cell.salt, info=None,
                               backend=default_backend()).derive(shared_key)
            self.serverList.append(
                Server(gonnect, sock, derived_key, ECprivate_key, RSA_key, gonnectport))
            #print("connected successfully to server @ " + gonnect + "   Port: " + str(gonnectport))
        except error:
            print("socket error occurred")

    def req(self, request, intermediate_servers):
        """send out stuff in router."""
        #print("REQUEST SENDING TEST")
        # must send IV and a cell that is encrypted with the next public key
        # public key list will have to be accessed in order with list of servers.
        # number between is to know when to stop i guess.
        # connection type. exit node always knows
        sendingCell = cell(request, Type="Req")
        IV = os.urandom(16)
        cipher = Cipher(algorithms.AES(intermediate_servers[2].key), modes.CBC(IV),
                        backend=default_backend())  # 256 bit length cipher lel
        encryptor = cipher.encryptor()  # encrypt the entire cell
        encrypted = encryptor.update(padder128(pickle.dumps(sendingCell)))
        encrypted += encryptor.finalize()  # finalise encryption.
        sendingCell = cell(encrypted, IV=IV, Type="relay")
        sendingCell.ip = intermediate_servers[2].ip
        sendingCell.port = intermediate_servers[2].port
        sendingCell = cell(pickle.dumps(sendingCell), Type="relay")

        IV = os.urandom(16)
        cipher = Cipher(algorithms.AES(intermediate_servers[1].key), modes.CBC(IV),
                        backend=default_backend())  # 256 bit length cipher lel
        encryptor = cipher.encryptor()  # encrypt the entire cell
        encrypted = encryptor.update(padder128(pickle.dumps(sendingCell)))
        encrypted += encryptor.finalize()  # finalise encryption.
        sendingCell = cell(encrypted, IV=IV, Type="relay")
        sendingCell.ip = intermediate_servers[1].ip
        sendingCell.port = intermediate_servers[1].port
        sendingCell = cell(pickle.dumps(sendingCell), Type="relay")
        IV = os.urandom(16)

        cipher = Cipher(algorithms.AES(intermediate_servers[0].key), modes.CBC(IV),
                        backend=default_backend())  # 256 bit length cipher lel
        encryptor = cipher.encryptor()  # encrypt the entire cell
        encrypted = encryptor.update(padder128(pickle.dumps(sendingCell)))
        encrypted += encryptor.finalize()  # finalise encryption.
        sendingCell = cell(encrypted, IV=IV, Type="relay")
        sendingCell.ip = intermediate_servers[0].ip
        sendingCell.port = intermediate_servers[0].port
        try:
            sock = intermediate_servers[0].socket
            sock.send(pickle.dumps(sendingCell))  # send over the cell
            their_cell = sock.recv(32768)  # await answer
            # you now receive a cell with encrypted payload.
            #print("received cell")
            # print(len(their_cell))
            # print(their_cell)
            their_cell = pickle.loads(their_cell)
            #print("received cell payload")
            # print(their_cell.payload)
            counter = 0
            while counter < len(intermediate_servers):
                cipher = Cipher(algorithms.AES(intermediate_servers[counter].key), modes.CBC(their_cell.IV),
                                backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(their_cell.payload)
                decrypted += decryptor.finalize()  # finalise decryption
                their_cell = pickle.loads(decrypted)
                counter += 1
                if(counter < len(intermediate_servers)):
                    their_cell = pickle.loads(their_cell.payload)

            if (their_cell.type == their_cell._Types[3]):
                #print("FAILED AT CONNECTION!")
                return

            response = pickle.loads(their_cell.payload)
            if not isinstance(response, type("")):
                print(response.content)
                print(response.status_code)
                return_dict = {"content": response.content.decode(
                    response.encoding), "status code": response.status_code}
                print(json.dumps(return_dict))
            else:
                print(json.dumps({"content": "FAILED!", "status code": 404}))
        except error:
            print("socketerror")


if __name__ == "__main__":
    me = Client()
    given = sys.argv

    if len(given) == 11:
        # TODO - refactor and use argument parsers. See https://docs.python.org/3/library/argparse.html

        for i in range(len(given)):
            if given[i] == "localhost":
                given[i] = gethostbyname(gethostname())

        given[2] = int(given[2])
        given[5] = int(given[5])
        given[8] = int(given[8])

        # set up static chain.
        # TODO - get the client to query a directory for the server keys instead of manually getting
        tempopen = open("publics/publictest" + given[3] + ".pem", "rb")
        publickey = serialization.load_pem_public_key(
            tempopen.read(), backend=default_backend())
        tempopen.close()
        me.firstConnect(given[1], given[2], publickey)

        tempopen = open("publics/publictest" + given[6] + ".pem", "rb")
        publickey = serialization.load_pem_public_key(
            tempopen.read(), backend=default_backend())
        tempopen.close()
        me.moreConnect1(given[4], given[5], me.serverList, publickey)

        tempopen = open("publics/publictest" + given[9] + ".pem", "rb")
        publickey = serialization.load_pem_public_key(
            tempopen.read(), backend=default_backend())
        tempopen.close()
        me.moreConnect2(given[7], given[8], me.serverList, publickey)

        me.req(given[10], me.serverList)
    else:
        print("insufficient arguments\n" +
              "<Server 1 IP> <Server 1 Port> <key 1 number> <Server 2 IP> <Server 2 Port> <key 2 number> <Server 3 IP> <Server 3 Port> <key 3 number> <Website>\n" +
              "if localhost is IP, just leave it as localhost")
