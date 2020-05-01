import rsa
from ca import CA, Certifcate
from elgamal import ElgamalDigitalSignature
# from utils import verifyCertificate
from simulation_config import ELG_PARAMS_PATH, CA_PKEY_NAME
import json
import os
# from utils import HexToBytes
from binascii import unhexlify as hexStrToBytes

class Receiver():
    def __init__(self, id, elgamal=None, persist=False):
        self.id = id
        self.lastRecInfo = {}
        self.persist = persist
        self.ca = CA.get_instance()
        self.caKey = self._loadCAKey()
        if(elgamal):
            self.elgSig = elgamal
        elif(os.path.exists(ELG_PARAMS_PATH)):
            self.elgSig = ElgamalDigitalSignature.from_file(ELG_PARAMS_PATH)
        else:
            self.elgSig = ElgamalDigitalSignature()
            self.elgSig.saveConfig(ELG_PARAMS_PATH)
        x = rsa.getAsymKey()
        self.privateKey = x
        self.publicKey = x.public_key()
        self._authenticateWithCA()

    
    def onReceive(self, message):
        self.lastRecInfo = {} # clearing the past info
        message = json.loads(message)
        message, senderID, signature = message["message"], message.get("sender", "UNKNOWN"), message["signature"]
        self._persist(message, "messageHex") ; self._persist(senderID, "senderID") ; self._persist(signature, "signature")
        senderCertificate = self.ca.getCertificate(senderID) ; self._persist(senderCertificate, "senderCertificate")
        if not self._verifyCertificate(senderCertificate):
            print("can't verify the certificate, it is not from the CA :(")
            self._persist(False, "certificateVer")
            return
        self._persist(True, "certificateVer")
        message = hexStrToBytes(message) ; self._persist(message, "messageBytes")
        message = rsa.decrypt(message, self.privateKey).decode("UTF-8") ; self._persist(message, "plainText")

        senderPubKey = senderCertificate.publicKey
        isValidSig = self.elgSig.verify(message, senderPubKey, signature) ; self._persist(isValidSig, "messageVer")
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

    def _persist(self, var, key):
        if self.persist:
            self.lastRecInfo[key] = var


def main(rid="test.security.rec.bob"):
    bob = Receiver(rid, persist=True)
    import simio as io
    from simulation_config import TEST_CASES_OUT_PATH
    number = 1
    for messageID, message in io.listen(bob.id):
        bob.onReceive(message)
        # save output
        r, s = bob.lastRecInfo["signature"]
        os.makedirs(TEST_CASES_OUT_PATH, exist_ok=True)
        loc = os.path.join(TEST_CASES_OUT_PATH, str(number) + "_rec.txt" )
        with open(loc, "w") as outfile:
            print(
                bob.elgSig.N,
                bob.elgSig.p,
                bob.elgSig.g,
                rsa.getBytes(bob.publicKey), # generated rsa public key
                rsa.getBytes(bob.privateKey), # generated rsa private key
                bob.lastRecInfo["certificateVer"], # does the certificate is coming from the trusted CA
                r, # r component of the signature
                s, # s component of the signature
                bob.lastRecInfo.get("messageVer", "None"), # does the message is really come from that sender
                bob.lastRecInfo.get("messageHex", "None"), # the message cipher to be deciphered in hex format
                bob.lastRecInfo.get("plainText", "None"), # the final plain text obtained from the whole process
             sep="\n", file=outfile)
        print(f"output saved at {loc}")
        number += 1


if __name__ == "__main__":
    from fire import Fire
    Fire(main)
    # import sys
    # recId = sys.argv[1] if len(sys.argv) >= 2 else "test.security.rec.bob"
    # bob = Receiver(recId)
    # import simio as io
    # for messageID, message in io.listen(bob.id):
    #     bob.onReceive(message)
