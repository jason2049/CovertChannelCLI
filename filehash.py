import hashlib
import base64

def getFileHash(filename):
    openedFile = open(filename, encoding='cp437')
    readFile = openedFile.read().encode('utf-8')
    
    md5Hash = hashlib.md5(readFile)
    md5Hashed = md5Hash.hexdigest()
    
    return md5Hashed
