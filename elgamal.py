'''
    plain implementation of the ElGamal signature algorithm
'''


import json
from random import randint
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import hashlib
import Crypto.Util.number as num
from Crypto.Hash import SHA256 as sha
from utils import strToBytes


def default_hash_SHA256(message):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    digest = digest.finalize()
    hexdigest = lambda digest: "".join(["%02x" % x for x in digest])
    return int(hexdigest(digest), 35)

def hashlib_sha(message):
    hashobj = hashlib.sha256(message)
    val = int.from_bytes(hashobj.digest(), 'big')
    return val

def sha256(message):
    h = sha.new()
    h.update(message)
    return int(h.hexdigest(), 35)

class ElgamalDigitalSignature():
    def __init__(self, N=2048, p=None, h=sha256, g=None):
        '''
            N: key length
            p: N-bit prime number
            h: hash function
            g: generator g < p of the multiplicative group of integers modulo p, Zp*
        '''
        # for parameter generation
        # 1. Choose a key length N
        #   this will be passed or defaulted to 2048
        # 2. Choose a cryptographic hash function h with output length L bits. If L>N, only the leftmost N bits of the hash output are used.
        #   this will be defaulted to SHA256
        # 3. Choose a generator g < p such that g belongs to GF(p)
        #   and because p is prime so g will be any number from {1...p-1} 

        self.N = N
        self.p = p or num.getPrime(self.N)
        # print("is p prime:", num.isPrime(self.p))
        self.h = h
        self.g = g or self.rand_g()

    @classmethod
    def from_file(cls, filePath):
        with open(filePath) as jsonFile:
            config = json.load(jsonFile)
        N = int(config["N"])
        p = int(config["p"])
        # h = config["h"]
        h = sha256
        g = int(config["g"])
        return cls(N, p, h, g)

    def saveConfig(self, filePath):
        config = {}
        config["N"] = self.N 
        config["p"] = self.p 
        # config["h"] = self.h # TODO: save it as string
        config["g"] = self.g
        with open(filePath, "w") as f:
            json.dump(config, f)


    def generateUserKey(self):
        '''
            generates a new pair of keys
            returns tuple of (private_key(x), public_key(y))
        '''
        # choose integer random x from {1...p-2}
        # computes y = g^x mod p
        # x is the private key, and y is the public key
        x = randint(1, self.p - 2)
        y = pow(self.g, x, self.p)
        return x, y

    def rand_g(self):
        return randint(2, self.p - 1)

    def rand_k(self):
        while True:
            k = randint(1, self.p-2)
            if num.GCD(k, self.p-1) == 1: # k should be relatively prime to p-1
                return k

    def sign(self, m, x):
        '''
        :param m: message
        :param x: private key of the signer
        '''
        # choose an integer k randomly from {2...p-2} with k relatively prime to p-1
        # compute r = pow(g, k, p)
        # compute s = (h(m) - xr) * modinverse k, p-1 and s != 0
        m = strToBytes(m)
        k = self.rand_k()
        r = pow(self.g, k, self.p)
        kinverse = num.inverse(k, self.p-1)
        s = (self.h(m) - x*r)*kinverse % (self.p -1)
        if(s == 0):
            return self.sign(m, x) # TODO: consider iterating instead
        return r, s

    def verify(self, m, y, signature):
        '''
        :param m: message
        :param y: public key of the signer
        '''
        # conditions are
        # 1. 0 < r < p, 0 < s < p-1
        # 2. pow(g, h(m)) equivalent pow(y, r)*pow(r, s) (modulo p)
        m = strToBytes(m)
        r, s = signature
        return all([
            r > 0, r < self.p,
            s > 0, s < self.p-1,
            pow(self.g, self.h(m), self.p) == pow(y, r, self.p)%self.p * pow(r, s, self.p) % self.p
        ])
        lhs = pow(self.g, self.h(m), self.p)
        rhs = pow(y, r, self.p)%self.p * pow(r, s, self.p) % self.p # we apply % self.p after every operation because it is modulo p
        return lhs == rhs

def test():
    elg = ElgamalDigitalSignature(N=6)
    for i in range(1000):
        m = b"Ammar Alsayed"
        x, y = elg.generateUserKey()
        sig = elg.sign(m, x)
        verified = elg.verify(m, y, sig)
        if (not verified):
            print(f"we only passed {i} random tests")
            print(f"sig={sig} x={x} y={y} p={elg.p} g={elg.g}")
            raise Exception("expected to verify but not verified :(")
        # notVerified = elg.verify(m, y, (sig[0] - 1, sig[1] + 1))
        notVerified = elg.verify(b's'+  m + b'e', y, sig)
        if (notVerified):
            print(f"we only passed {i} random tests")
            print(f"{sig=} {x=} {y=} {elg.p=} {elg.g=} ")
            raise Exception("expected to not verify but verified :(")
        if (i+1) % 50 == 0:
            print(f"{i+1} tests passed")

if __name__ == "__main__":
    test()
    m = b"ammar alsayed"
    crypto = default_hash_SHA256(m)
    cryptography = sha256(m)
    hashlib = hashlib_sha(m)
    print("crypto", crypto)
    print("crypt+", cryptography)
    # print("haslib", hashlib)
    # print('%064x' % hashlib)
    pass