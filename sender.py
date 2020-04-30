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
    def __init__(self, id, elgamal=None, elgKeyPairs=None):
        '''
        :param elgamal: elgamal object of Elgamal class type, if None a new one will be created with default params or will be restored from the file
        :param elgKeyPairs: key pairs generated from same parameters of elgamal object. if None they will be generated from elgamal object
        '''
        self.id = id
        self.ca = CA.get_instance() # this should be called before loading cakey
        self.caKey = self._loadCAKey()
        if(elgamal):
            self.elgSig = elgamal
        elif(os.path.exists(ELG_PARAMS_PATH)):
            self.elgSig = ElgamalDigitalSignature.from_file(ELG_PARAMS_PATH)
        else:
            self.elgSig = ElgamalDigitalSignature()
            self.elgSig.saveConfig(ELG_PARAMS_PATH)

        x, y = elgKeyPairs or self.elgSig.generateUserKey()
        self.privateKey = x
        self.publicKey = y
        self._authenticateWithCA()

    
    def sendTo(self, whoId, message):
        signature = self.elgSig.sign(message, self.privateKey)
        recCertificate = self.ca.getCertificate(whoId)
        # TODO: verifyCertificate
        if (not self._verifyCertificate(recCertificate)):
            print("can't verify the certificate, it is not from the CA :(")
            return
        message = rsa.encrypt(message, recCertificate.publicKey)
        message = strHexOfBytes(message)
        # print("Encrypted message", message)
        io.send(whoId, {"sender":self.id , "message": message, "signature": signature})

    def _loadCAKey(self):
        return rsa.loadKey("ca.public.pem")

    def _verifyCertificate(self, certificate):
        input(f"message in _ver = {rsa.getBytes(certificate.publicKey)}")
        return rsa.verify(certificate.signature, rsa.getBytes(certificate.publicKey), self.caKey)

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