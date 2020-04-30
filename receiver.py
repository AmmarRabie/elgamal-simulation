import rsa
from ca import CA, Certifcate
from elgamal import ElgamalDigitalSignature
# from utils import verifyCertificate
from simulation_config import ELG_PARAMS_PATH, CA_PKEY_NAME
import json
# from utils import HexToBytes
from binascii import unhexlify as hexStrToBytes

class Receiver():
    def __init__(self, id):
        self.id = id
        self.lastRecInfo = None
        self.ca = CA.get_instance()
        self.caKey = self._loadCAKey()
        self.elgSig = ElgamalDigitalSignature.from_file(ELG_PARAMS_PATH) # never make the receiver init the elgamal, [steps.jpg]
        x = rsa.getAsymKey()
        self.privateKey = x
        self.publicKey = x.public_key()
        self._authenticateWithCA()

    
    def onReceive(self, message):
        message = json.loads(message)
        message, senderID, signature = message["message"], message.get("sender", "UNKNOWN"), message["signature"]
        senderCertificate = self.ca.getCertificate(senderID)
        if not self._verifyCertificate(senderCertificate):
            print("can't verify the certificate, it is not from the CA :(")
            return
        message = hexStrToBytes(message)
        message = rsa.decrypt(message, self.privateKey).decode("UTF-8")

        senderPubKey = senderCertificate.publicKey
        isValidSig = self.elgSig.verify(message, senderPubKey, signature)
        if(not isValidSig):
            print("invalid signature from user", senderID)
            return False
        print(f"message '{message}' received from {senderID}")
        return True

    def _verifyCertificate(self, certificate):
        message = certificate.publicKey.to_bytes((certificate.publicKey.bit_length() + 7) // 8, 'big')
        return rsa.verify(certificate.signature, message, self.caKey)

    def _loadCAKey(self):
        return rsa.loadKey(CA_PKEY_NAME, private=False)

    def _authenticateWithCA(self):
        '''
            authenticate my self with Certificate authority
        '''
        self.ca.addCertificate(Certifcate(self.id, self.publicKey))


if __name__ == "__main__":
    bob = Receiver("test.security.rec.bob")
    import simio as io
    for messageID, message in io.listen(bob.id):
        bob.onReceive(message)
