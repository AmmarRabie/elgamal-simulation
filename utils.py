from faker import Faker
from random import choice
import os
from binascii import hexlify as bytesToHex, unhexlify as HexToBytes

fake = Faker()

def getId(fname=None, lname=None, company=None, tld=None):
    '''
        for every parameter, if it none appropriate random will generated
    '''
    components = []
    components.append(fname or fake.first_name())
    components.append(lname or fake.last_name())
    components.append(company or fake.company_suffix())
    tlds = ["com", "net", "org", "ai", "edu", "gov"]
    components.append(choice(tlds))
    components = [c.replace(" ", "") for c in components]
    return ".".join(reversed(components))
    # return ".".join(components)


def strToBytes(strOrBytes):
    '''ensures that the passed object will be bytes'''
    if(isinstance(strOrBytes, str)):
        return strOrBytes.encode("UTF-8")
    if(isinstance(strOrBytes, bytes)):
        return strOrBytes
    raise TypeError(f"{strOrBytes} should be string or bytes, can't be converted to bytes")

def bytesToStr(strOrBytes):
    if(isinstance(strOrBytes, str)):
        return strOrBytes
    if(isinstance(strOrBytes, bytes)):
        return strOrBytes.decode("UTF-8")
    raise TypeError(f"{strOrBytes} should be string or bytes, can't be converted to str")


if __name__ == "__main__":
    print(getId())
    print(getId())
    print(getId())
    print(getId())