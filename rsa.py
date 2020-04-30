# RSA encryption using lib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from utils import strToBytes

# print(isinstance(key, rsa.RSAPrivateKeyWithSerialization))
# print(type(key.public_key()))
default_enc_padding = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
    )
default_sign_padding = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH)

def encrypt(plainText, publicKey):
    plainText = strToBytes(plainText)
    return publicKey.encrypt(plainText, default_enc_padding)


def decrypt(cipherText, privateKey):
    cipherText = strToBytes(cipherText)
    return privateKey.decrypt(cipherText, default_enc_padding)

def sign(message, privateKey):
    message = strToBytes(message)
    return privateKey.sign(message, default_sign_padding, hashes.SHA256())

def verify(signature, message, publicKey):
    message = strToBytes(message)
    try:
        publicKey.verify(signature, message, default_sign_padding, hashes.SHA256())
        return True
    except InvalidSignature as e:
        return False

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

def test():
    # generate
    print("generating...")
    privateKey = getAsymKey()
    publicKey = privateKey.public_key()

    # save
    print("saving...")
    saveKey(privateKey, "k")
    saveKey(publicKey, "k")

    # load
    print("loading...")
    privateKey2 = loadKey("k.private.pem")
    publicKey2 = loadKey("k.public.pem")

    # cmp
    print("comparing bytes...")
    getPubBytes = lambda k: k.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    getPrivBytes = lambda k: k.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
    assert getPubBytes(publicKey) == getPubBytes(publicKey2)
    assert getPrivBytes(privateKey) == getPrivBytes(privateKey2)

    # clean
    from os import remove
    remove("k.private.pem")
    remove("k.public.pem")

    # cmp encryption and decryption
    print("encrypting and decrypting...")
    plainText = b"encrypted data"
    cipherText = encrypt(plainText, publicKey)
    decryptedText = decrypt(cipherText, privateKey2)
    assert plainText == decryptedText

    print("Testing signing and verification..")
    signature = sign(plainText, privateKey)
    assert verify(signature, plainText, publicKey)
    assert verify(signature, "other text", publicKey) == False

    print("tests passed")

if __name__ == "__main__":
    test()