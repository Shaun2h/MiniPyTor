"""Server class file"""

import pickle
import os
import select
import sys
import requests

from socket import *
from struct import *
from random import randint

import cryptography.hazmat.primitives.asymmetric.padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from util import padder128
from celldef import cell

class Client():
    """Client class"""
    def __init__(self, sock, key, generated_key):
        self.socket = sock
        self.key = key  # the derived key
        # the generated elliptic curve diffie hellman key.
        self.generated_key = generated_key
        self.bounce_ip = None
        self.bounce_port = None
        self.bounce_socket = None


class Server():
    """Server class"""
    CLIENTS = []
    CLIENTSOCKS = []

    def __init__(self, port_number, identity):
        tempopen = open("privates/privatetest"+str(identity)+".pem", "rb")
        self.true_private_key = serialization.load_pem_private_key(tempopen.read(
        ), password=None, backend=default_backend())  # used for signing, etc.
        # public key for sending out.
        self.sendingpublickey = self.true_private_key.public_key()
        # tcp type chosen for first.
        self.server_socket = socket(AF_INET, SOCK_STREAM)
        # now you have a signature of your own damned public key.
        # better be "" or it'll listen only on localhost
        self.server_socket.bind(("", port_number))
        self.server_socket.listen(100)

    def exchange_keys(self, clientsocket, obtainedCell):
        """Exchange Key with someone, obtaining a shared secret. Also, generate salt
        and pass it back to them with your private key."""

        private_key = ec.generate_private_key(
            ec.SECP384R1(), default_backend())  # elliptic curve
        public_key = private_key.public_key()  # duh same.
        serialised_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        # serialise the public key that I'm going to send them

        theirkey = serialization.load_pem_public_key(
            obtainedCell.payload, backend=default_backend())
        shared_key = private_key.exchange(ec.ECDH(), theirkey)
        salty = str.encode(str(randint(0, 99999999)))  # randomised IV
        derived_key = HKDF(algorithm=hashes.SHA256(
        ), length=32, salt=salty, info=None, backend=default_backend()).derive(shared_key)
        reply_cell = cell(serialised_public_key,
                          salt=salty, Type="ConnectResp")
        signature = self.true_private_key.sign(salty,
                                               cryptography.hazmat.primitives.asymmetric.padding.PSS(
                                                   mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(
                                                       hashes.SHA256()),
                                                   salt_length=cryptography.hazmat.primitives.asymmetric.padding.PSS.MAX_LENGTH), hashes.SHA256())
        reply_cell.signature = signature  # assign the signature.
        print("reply cell")
        print(pickle.dumps(reply_cell))
        # send them the serialised version.
        clientsocket.send(pickle.dumps(reply_cell))
        return private_key, derived_key

    def decrypt(self, thing):
        """ thing that is in RSA encryption must be decrypted before continuing."""
        return self.true_private_key.decrypt(thing, cryptography.hazmat.primitives.asymmetric.padding.OAEP(
            mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    def main(self):
        """main method"""
        client_class = None  # initialise as none.
        readready, _, _ = select.select(
            [self.server_socket] + self.CLIENTSOCKS, [], [])
        for i in readready:
            if (i == self.server_socket):  # i've gotten a new connection
                print("client get")
                (clientsocket, _) = self.server_socket.accept()
                # clientsocket.setblocking(0)
                clientsocket.settimeout(0.3)
                try:
                    obtainedCell = clientsocket.recv(
                        4096)  # obtain their public key
                    try:
                        print("raw data obtained. (Cell)")
                        print(obtainedCell)
                        # decrypt the item.
                        obtainedCell = self.decrypt(obtainedCell)

                    # this is due to decryption failure.
                    except ValueError:
                        if client_class is not None:
                            self.CLIENTS.remove(client_class)
                            # just in case.
                            # otherwise, it should continue
                        print("rejected one connection")
                        continue
                    print("decrypted cell with actual keys.")
                    print(obtainedCell)
                    # i.e grab the cell that was passed forward.
                    obtainedCell = pickle.loads(obtainedCell)
                    print("after pickle load")
                    print(obtainedCell)
                    if obtainedCell.type != "AddCon":
                        break  # it was not a connection request.
                    # obtain the generated public key, and the derived key.
                    generatedPrivateKey, derivedkey = self.exchange_keys(
                        clientsocket, obtainedCell)
                    client_class = Client(
                        clientsocket, derivedkey, generatedPrivateKey)
                    self.CLIENTS.append(client_class)
                    self.CLIENTSOCKS.append(clientsocket)
                    print(client_class.socket.getpeername())
                    print("Connected to ONE client.\n\n\n")

                # error is socket error here.
                except (error, ConnectionResetError, timeout):
                    print("socket ERROR! might have timed out.")
                    if client_class is not None:
                        self.CLIENTS.remove(client_class)
                        # just in case.
                        # otherwise, it should continue
                    continue

            else:  # came from an existing client.
                try:
                    for k in self.CLIENTS:
                        if k.socket == i:
                            sending_client = k
                    received = i.recv(4096)
                    print("got a packet..")
                    print(received)
                    if not received:
                        raise ConnectionResetError
                except (error, ConnectionResetError, ConnectionAbortedError, timeout):
                    print("Client was closed or timed out.")
                    sending_client.socket.close()
                    if sending_client.bounce_socket is not None:
                        sending_client.bounce_socket.close()
                    self.CLIENTSOCKS.remove(i)
                    self.CLIENTS.remove(sending_client)
                    continue
                print("existing")
                # received_data = self.decrypt(received)
                gottencell = pickle.loads(received)
                derived_key = sending_client.key  # take his derived key
                cipher = Cipher(algorithms.AES(derived_key), modes.CBC(
                    gottencell.IV), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(gottencell.payload)
                decrypted += decryptor.finalize()
                cell_to_next = pickle.loads(decrypted)
                print(cell_to_next.type)
                if cell_to_next.type == "relay connect":  # is a request for a relay connect
                    try:
                        # your connection is TCP.
                        sock = socket(AF_INET, SOCK_STREAM)
                        sock.connect((cell_to_next.ip, cell_to_next.port))
                        print((cell_to_next.ip, cell_to_next.port))
                        print("cell to next")
                        print(decrypted)
                        print("payload")
                        print(cell_to_next.payload)
                        # send over the cell payload
                        sock.send(cell_to_next.payload)
                        theircell = sock.recv(4096)  # await answer
                        print("got values")
                        print(theircell)
                        IV = os.urandom(16)
                        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(
                            IV), backend=default_backend())
                        encryptor = cipher.encryptor()
                        if(theircell == b""):
                            encrypted = encryptor.update(padder128(
                                pickle.dumps(cell("", Type="failed"))))
                            encrypted += encryptor.finalize()
                            print("sent failed")
                            i.send(pickle.dumps(
                                cell(encrypted, IV=IV, Type="failed")))
                        else:
                            encrypted = encryptor.update(padder128(
                                pickle.dumps(cell(theircell, Type="ConnectResp"))))
                            encrypted += encryptor.finalize()
                            print("sent valid response")
                            i.send(pickle.dumps(
                                cell(encrypted, IV=IV, Type="AddCon")))
                            sending_client.bounce_ip = cell_to_next.ip
                            sending_client.bounce_port = cell_to_next.port
                            sending_client.bounce_socket = sock
                            print("connection success.\n\n\n\n\n")
                    except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError, error, timeout)as e:
                        print(
                            "failed to connect to other server. sending back failure message, or timed out.")
                        IV = os.urandom(16)
                        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(
                            IV), backend=default_backend())
                        encryptor = cipher.encryptor()
                        encrypted = encryptor.update(padder128(pickle.dumps(
                            cell(pickle.dumps(cell("CONNECTIONREFUSED", Type="failed")), Type="failed"))))
                        encrypted += encryptor.finalize()
                        i.send(pickle.dumps(
                            cell(encrypted, IV=IV, Type="failed")))
                        print("sent back failure message.")

                # is an item to be relayed.
                elif cell_to_next.type == "relay":
                    if sending_client.bounce_socket is None:  # check if there is bounce socket
                        return
                    sock = sending_client.bounce_socket
                    print("bouncing cell's decrypted..")
                    print(decrypted)
                    print("payload")
                    print(cell_to_next.payload)
                    print(cell_to_next.type)
                    sock.send(cell_to_next.payload)  # send over the cell
                    try:
                        theircell = sock.recv(32768)  # await answer
                    except timeout:
                        theircell = "request timed out!"
                    print("got answer back.. as a relay.")
                    print(len(theircell))
                    print(theircell)
                    IV = os.urandom(16)
                    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(
                        IV), backend=default_backend())
                    encryptor = cipher.encryptor()
                    encrypted = encryptor.update(
                        padder128(pickle.dumps(cell(theircell, Type="ConnectResp"))))
                    encrypted += encryptor.finalize()
                    i.send(pickle.dumps(
                        cell(encrypted, IV=IV, Type="AddCon")))
                    print("Relay success.\n\n\n\n\n")
                elif cell_to_next.type == "Req":
                    print(cell_to_next.payload)
                    if isinstance(cell_to_next.payload, type("")):
                        request = cell_to_next.payload
                        try:
                            header = {
                                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"}
                            a = requests.get(request, headers=header)
                            print("length of answer")
                            print(len(a.content))
                        except requests.exceptions.ConnectionError:
                            a = "ERROR"
                            print("failed to receive a response from the website.")

                        IV = os.urandom(16)
                        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(
                            IV), backend=default_backend())
                        encryptor = cipher.encryptor()
                        encrypted = encryptor.update(
                            padder128(pickle.dumps(cell(pickle.dumps(a), Type="ConnectResp"))))
                        encrypted += encryptor.finalize()
                        i.send(pickle.dumps(
                            cell(encrypted, IV=IV, Type="AddCon")))
                        print("VALID REQUEST REPLIED.")
                    else:
                        IV = os.urandom(16)
                        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(
                            IV), backend=default_backend())
                        encryptor = cipher.encryptor()
                        encrypted = encryptor.update(padder128(pickle.dumps(
                            cell("INVALID REQUEST DUMDUM", Type="ConnectResp"))))
                        encrypted += encryptor.finalize()
                        i.send(pickle.dumps(
                            cell(encrypted, IV=IV, Type="AddCon")))
                        print("INVALID REQUEST SENT BACK")

if __name__ == "__main__":
    # TODO: use specific identity with a generator or something

    if len(sys.argv) == 2:
        identity = 3
        port = sys.argv[1]
        if port == "a":
            port = 45000
            identity = 0
        elif port == "b":
            port = 45001
            identity = 1
        elif port == "c":
            port = 45002
            identity = 2
    else:
        print("Usage: python Server.py #port")

    server = Server(int(port), identity)
    print("Started server on %d with identity %d" % (port, identity))

    while True:
        server.main()
