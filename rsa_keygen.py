from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
for i in range(100):
    a = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=4096) #used for signing, etc.
    privatebytes = a.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
    publicbytes = a.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    private = open("privates/privatetest"+str(i)+".pem","wb")
    private.write(privatebytes)
    public = open("publics/publictest"+str(i)+".pem","wb")
    public.write(publicbytes)
    private.close()
    public.close()
    privatetest = open("privates/privatetest"+str(i)+".pem","rb")
    print(privatetest.read() ==privatebytes)
    publictest =open("publics/publictest"+str(i)+".pem","rb")
    print(publictest.read() == publicbytes)
    privatetest.close()
    publictest.close()

for i in range(30):
    with open("privates/privatetest"+str(i)+".pem","rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
        key_file.close()
    with open("publics/publictest"+str(i)+".pem","rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
        key_file.close()


