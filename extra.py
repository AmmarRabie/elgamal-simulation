def verifyRequiredPackages():
    import sys
    try:
        import cryptography, Crypto, watchgod, faker, fire
        import Crypto.Util.number, Crypto.Hash
    except ImportError:
        sys.exit('''not all required packages are installed, please install packages in requirements.txt first to run the demo
        e.g 'pip install -r requirements.txt' ''')
verifyRequiredPackages()

from ca import CA
from sender import Sender
from receiver import Receiver
import json

def test():
    print("Generating dummy certificates")
    # CA.get_instance().generateDummyCertificates(n=10)
    print("creating the true sender alice")
    alice = Sender("alice.extra.py", persist=True)
    print("creating the receiver bob")
    bob = Receiver("bob.extra.py", persist=True)
    plainText = "hello bob, this is me alice from extra.py file :)"
    messagePath = alice.sendTo(bob.id, message=plainText)
    sendInfo = alice.lastSendInfo
    with open(messagePath) as messageFile:
        recTextOrig = messageFile.read()
    print("making an attack, try to change the message sended")
    recText = recTextOrig
    recJson = json.loads(recText)
    recJson["message"] += "56" # only one new char
    recText = json.dumps(recJson)

    try:
        bob.onReceive(recText)
        assert False, "receive should throw exception but it doesn't"
    except ValueError as e:
        print("value error because this message can't be decrypted")

    print("try to change the whole message content using bob public key (all people know the public key)")
    recText = recTextOrig
    recJson = json.loads(recText)
    import rsa
    from sender import strHexOfBytes
    evilMessage = "this is an evil message from attacker"
    recJson["message"] = strHexOfBytes(rsa.encrypt(evilMessage, bob.publicKey))
    recText = json.dumps(recJson)
    bob.onReceive(recText)
    lastInfo = bob.lastRecInfo
    print(lastInfo.get("plainText"))
    print("does the message signature valid ?", lastInfo.get("messageVer"))

        

if __name__ == "__main__":
    test()
