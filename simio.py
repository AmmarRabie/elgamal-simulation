'''
    simulate the network io between seders and receivers
'''
import hashlib
import time
import os
import json
from simulation_config import IO_BASE_DIR
from watchgod import watch, Change

def _getFileName():
    return hashlib.sha256(str(time.time_ns()).encode()).hexdigest()

def send(domain, payload):
    '''
        :param domain: to send to
        :param payload: the message you want to sent
    '''
    recDir = os.path.join(IO_BASE_DIR, domain)
    os.makedirs(recDir, exist_ok=True)
    messageID = _getFileName()
    with open(os.path.join(recDir, messageID), "w") as f:
        json.dump(payload, f)
    return os.path.join(recDir, messageID)

def listen(domain):
    '''
        :param domain: the domain that you want to listen for, any message received will be reported to you
        yields message_id, message
    '''
    listenDir = os.path.join(IO_BASE_DIR, domain)
    os.makedirs(listenDir, exist_ok=True)
    for changes in watch(listenDir):
        # changes is set of changes, every change is tuple of (changeClass, filePath)
        for c in changes:
            changeType, messageFilePath = c
            if changeType == Change.deleted:
                continue
            text = None
            with open(messageFilePath) as messageFile:
                text = messageFile.read()
            if text == None:
                raise RuntimeError("can't find read the message")
            messageID = os.path.basename(messageFilePath)
            yield messageID, text
