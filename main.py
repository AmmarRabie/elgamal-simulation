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

def test():
    print("Generating dummy certificates")
    # CA.get_instance().generateDummyCertificates(n=10)
    print("creating the sender alice")
    alice = Sender("alice.main.py", persist=True)
    print("creating the receiver bob")
    bob = Receiver("bob.main.py", persist=True)
    plainText = "hello bob, this is me alice from main.py file :)"
    messagePath = alice.sendTo(bob.id, message=plainText)
    sendInfo = alice.lastSendInfo
    with open(messagePath) as messageFile:
        recText = messageFile.read()

    bob.onReceive(recText)
    recInfo = bob.lastRecInfo
    
    print("plain text at sender", plainText)
    plainText2 = recInfo.get("plainText", None)
    print("plain text at receiver", plainText2)
    assert plainText == plainText2, "different values of sended message and received one"
    print("does the message signature valid ?", recInfo.get("messageVer"))

if __name__ == "__main__":
    test()
