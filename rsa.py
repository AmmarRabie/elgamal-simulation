# RSA encryption using lib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from utils import strToBytes

# print(isinstance(key, rsa.RSAPrivateKeyWithSerialization))
# print(type(key.public_key()))

default_padding = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
    )
    
def encrypt(plainText, publicKey):
    plainText = strToBytes(plainText)
    return publicKey.encrypt(plainText, default_padding)


def decrypt(cipherText, privateKey):
    cipherText = strToBytes(cipherText)
    return privateKey.decrypt(cipherText, default_padding)



def getAsymKey():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())



def saveKey(key, loc, private=None):
    '''
        private:
            True: force saving as private key
            False: force saving as public key
            None: auto detection of the type using isinstance
    '''
    if private == None:
        private = isinstance(key, rsa.RSAPrivateKey)
    loc += ".private.pem" if private else ".public.pem"
    with open(loc, "wb") as f:
        if private:
            f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            # encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
            encryption_algorithm=serialization.NoEncryption(),
            ))
        else:
            # save public key
            f.write(key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))

def loadKey(loc, private=None):
    '''
        private:
            None: auto predict from the loc path (.public | .pub) will be public otherwise false
    '''
    if private == None:
        private = loc.find(".pub") == -1 # support for .public and .pub
    elif(private):
        loc.find(".private") == -1
    elif(loc.find(".pub") == -1):
        loc += ".public.pem"
    with open(loc, "rb") as f:
        if private:
            private_key = serialization.load_pem_private_key(f.read(),password=None,backend=default_backend())
        else:
            private_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    return private_key

def getBytes(key):
    # TODO: use it inside saveKey
    # TODO: make private option
    return getPubBytes(key) if isinstance(key, rsa.RSAPublicKey) else getPrivBytes(key)
getPubBytes = lambda k: k.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
getPrivBytes = lambda k: k.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())

def isRSAInstance(key):
    return isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey))
if __name__ == "__main__":
    # generate
    privateKey = getAsymKey()
    publicKey = privateKey.public_key()

    # save
    saveKey(privateKey, "k")
    saveKey(publicKey, "k")

    # load
    privateKey2 = loadKey("k.private.pem")
    publicKey2 = loadKey("k.public.pem")

    # cmp
    getPubBytes = lambda k: k.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    getPrivBytes = lambda k: k.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
    print(getPubBytes(publicKey) == getPubBytes(publicKey2))
    print(getPrivBytes(privateKey) == getPrivBytes(privateKey2))

    # clean
    from os import remove
    remove("k.private.pem")
    remove("k.public.pem")

    # cmp encryption and decryption
    plainText = b"encrypted data"
    cipherText = encrypt(plainText, publicKey)
    decryptedText = decrypt(cipherText, privateKey2)
    print(plainText == decryptedText)