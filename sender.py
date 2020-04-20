import rsa
from ca import CA, Certifcate
from elgamal import ElgamalDigitalSignature
import json
import os
from simulation_config import ELG_PARAMS_PATH
import simio as io
# from utils import HexToBytes, bytesToHex
strHexOfBytes = lambda digest: "".join(["%02x" % x for x in digest])
# from utils import verifyCertificate

class Sender():
    def __init__(self, id):
        self.id = id
        self.caKey = self._loadCAKey()
        if(os.path.exists(ELG_PARAMS_PATH)):
            self.elgSig = ElgamalDigitalSignature.from_file(ELG_PARAMS_PATH)
        else:
            self.elgSig = ElgamalDigitalSignature()
            self.elgSig.saveConfig(ELG_PARAMS_PATH)

        x, y = self.elgSig.generateUserKey()
        self.privateKey = x
        self.publicKey = y
        self.ca = CA.get_instance()
        self._authenticateWithCA()

    
    def sendTo(self, whoId, message):
        signature = self.elgSig.sign(message, self.privateKey)
        recCertificate = self.ca.getCertificate(whoId)
        # TODO: verifyCertificate
        self._verifyCertificate(recCertificate)
        message = rsa.encrypt(message, recCertificate.publicKey)
        message = strHexOfBytes(message)
        # print("Encrypted message", message)
        io.send(whoId, {"sender":self.id , "message": message, "signature": signature})

    def _loadCAKey(self):
        return rsa.loadKey("ca.public.pem")

    def _verifyCertificate(self, certificate):
        pass

    def _authenticateWithCA(self):
        '''
            authenticate my self with Certificate authority
        '''
        self.ca.addCertificate(Certifcate(self.id, self.publicKey))


if __name__ == "__main__":
    alice = Sender("test.security.sender.alice")
    alice.sendTo("test.security.rec.bob", "Hello bob, this message is for sure from me.. you all can see this message :)")
    while(True):
        m = input("Enter message to send to bob: ")
        m = str(m)
        alice.sendTo("test.security.rec.bob", m)