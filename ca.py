from typing import TypeVar
from utils import getId as randID
import os
from time import sleep
import json

T = TypeVar('T', bound='CA')

# certificate authority simulation
class Certifcate():
    def __init__(self, ownerID, publicKey, timestamp=None, validAfter=None, validBefore=None):
        self.ownerID = ownerID
        self.publicKey = publicKey
        self.timestamp = timestamp
        self.validAfter = validAfter
        self.validBefore = validBefore
        
import rsa
def getCertificate(id):
    '''
        id: the id of the owner of the certificate
    '''
    pass


class CA():
    instance = None
    def __init__(self):
        '''
            generates the public and private key for the ca authority
            public key is saved in ca.pub file
            private key is stored in privateKey
        '''
        self.privateKey = rsa.getAsymKey()
        pubKey = self.privateKey.public_key()
        rsa.saveKey(pubKey, "ca")

        self.storeDir = "ca_store"

    @staticmethod
    def get_instance() -> T:
        CA.instance = CA.instance or CA()
        return CA.instance

    def getCertificate(self, targetID):
        '''
            targetID: the targetID of the owner of the certificate
        '''
        candidates = filter(lambda x: x.find(targetID) == 0, os.listdir(self.storeDir)) # we compare with 0 to restrict to match from the beginning of the file path
        loc = max(candidates, default="", key=lambda x: len(x))
        loc = os.path.join(self.storeDir, loc)
        if(loc.endswith(".pem")):
            key = rsa.loadKey(loc)
        elif(loc.endswith(".o")):# TODO: change it to .json
            with open(loc) as f:
                fileData = json.load(f)
                key = fileData["public_key"]
        else:
            print(f"Warning: can't get a certificate of {targetID}")
            return None # we can't find this targetID
        return Certifcate(targetID, key)
    
    def generateDummyCertificates(self, n=100):
        for i in range(n):
            currentID = randID()
            currentPub = rsa.getAsymKey().public_key()
            loc = os.path.join(self.storeDir, currentID)
            rsa.saveKey(key=currentPub, loc=loc) # TODO: use getBytes instead and save all certificate info

    def addCertificate(self, certificate:Certifcate):
        '''
            id: the id of the new certificate
            certificate: certificate CX09 information that will be stroed
                type ca.Certificate
        '''
        if(not self._authenticateCaller()):
            raise RuntimeError("authentication error")
        # TODO: save all information in the certificate
        currentPub = certificate.publicKey
        loc = os.path.join(self.storeDir, certificate.ownerID)
        if(rsa.isRSAInstance(currentPub)):
            rsa.saveKey(key=currentPub, loc=loc) # TODO: use getBytes instead and save all certificate info
        elif(currentPub):
            with open(loc + f".pub.o", 'w') as f:
                json.dump({"public_key": currentPub}, f)
        else:
            raise TypeError("public key is not a valid key")
    


    def _authenticateCaller(self, t=3, step=1):
        # simulation only
        print("Make sure that the caller is the owner of the resources.", end="", flush=True)
        for _ in range(0, t, step):
            print(".", end="", flush=True)
            sleep(1)
        return True





if __name__ == "__main__":
    CA.get_instance()._authenticateCaller()