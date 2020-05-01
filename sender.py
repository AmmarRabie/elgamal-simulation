import rsa
from ca import CA, Certifcate
from elgamal import ElgamalDigitalSignature
import json
import os
from simulation_config import ELG_PARAMS_PATH, TEST_CASES_IN_PATH, TEST_CASES_OUT_PATH
import simio as io
# from utils import HexToBytes, bytesToHex
strHexOfBytes = lambda digest: "".join(["%02x" % x for x in digest])
# from utils import verifyCertificate

class Sender():
    def __init__(self, id, elgamal=None, elgKeyPairs=None, persist=False):
        '''
        :param elgamal: elgamal object of Elgamal class type, if None a new one will be created with default params or will be restored from the file
        :param elgKeyPairs: key pairs generated from same parameters of elgamal object. if None they will be generated from elgamal object
        '''
        self.id = id
        self.lastSendInfo = {}
        self.persist = persist
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
        self.lastSendInfo = {} # clearing the past info
        signature = self.elgSig.sign(message, self.privateKey) ; self._persist(signature, "signature")
        recCertificate = self.ca.getCertificate(whoId) ; self._persist(recCertificate, "recCertificate")
        # TODO: verifyCertificate
        if (not self._verifyCertificate(recCertificate)):
            print("can't verify the certificate, it is not from the CA :(")
            self._persist(False, "certificateVer")
            return
        self._persist(True, "certificateVer")
        message = rsa.encrypt(message, recCertificate.publicKey) ; self._persist(message, "cipherBytes")
        message = strHexOfBytes(message) ; self._persist(message, "cipherHex")
        # print("Encrypted message", message)
        io.send(whoId, {"sender":self.id , "message": message, "signature": signature})

    def _loadCAKey(self):
        return rsa.loadKey("ca.public.pem")

    def _verifyCertificate(self, certificate):
        return rsa.verify(certificate.signature, rsa.getBytes(certificate.publicKey), self.caKey)

    def _authenticateWithCA(self):
        '''
            authenticate my self with Certificate authority
        '''
        self.ca.addCertificate(Certifcate(self.id, self.publicKey))
    
    def _persist(self, var, key):
        if self.persist:
            self.lastSendInfo[key] = var

class SenderApp():
    def __init__(self, sid="test.security.sender.alice", rid = "test.security.rec.bob"):
        self.sid = sid
        self.rid = rid
        # 1. generate private/public key pairs for the certificate authority.
        # 2. Initially generate some X509 certificates for random public keys, for random ids and store them in a suitable format (a file or a database)
        # CA.get_instance().generateDummyCertificates()

    def testcases(self):
        '''
            run a sender with test cases included in TEST_PATH_DIR (see simulation_config.py)
        '''
        messages = []
        for testnumber in os.listdir(TEST_CASES_IN_PATH):
            testpath = os.path.join(TEST_CASES_IN_PATH, testnumber)
            with open(testpath, 'r') as testfile:
                testcase = testfile.read()
            messages.append(testcase)
        return self.run(testcases=messages)
                # output all information. N, p, g, x1, y1, x2, y2, r, s
    def run(self, testcases=[]):
        '''
            run a sender
        '''
        alice = Sender(self.sid, persist=True)
        for testnumber, testcase in enumerate(testcases):
            alice.sendTo(self.rid, testcase)
            self._saveOutput(alice, str(testnumber + 1) + "_sender.txt")
        while(True):
            m = input(f"Enter message to send to {self.rid}: ")
            m = str(m)
            if(m in ["", ":q", ":Q", "exit", "stop"]):
                break
            alice.sendTo(self.rid, m)
    def _saveOutput(self, sender, caseId):
        loc = os.path.join(TEST_CASES_OUT_PATH, caseId)
        os.makedirs(TEST_CASES_OUT_PATH, exist_ok=True)
        pubKey = sender.publicKey
        privKey = sender.privateKey
        elgp, elgg, elgN = sender.elgSig.p, sender.elgSig.g, sender.elgSig.N
        r, s = sender.lastSendInfo["signature"]
        # cipherBytes = sender.lastSendInfo["cipherBytes"]
        cipherHex = sender.lastSendInfo.get("cipherHex", "None")
        with open(loc, "w") as outfile:
            print(elgN, elgp, elgg, pubKey, privKey, r, s, cipherHex, sep="\n", file=outfile)
            # print (cipherBytes, sep="\n", file=outfile)
        print(f"output saved at {loc}")

if __name__ == "__main__":
    from fire import Fire
    Fire(SenderApp)
    # alice = Sender("test.security.sender.alice")
    # alice.sendTo("test.security.rec.bob", "Hello bob, this message is for sure from me.. you all can see this message :)")
    # while(True):
    #     m = input("Enter message to send to bob: ")
    #     m = str(m)
    #     alice.sendTo("test.security.rec.bob", m)