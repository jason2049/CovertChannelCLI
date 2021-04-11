from string import ascii_uppercase
import sys
import os
import getpass
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
import base64

def secure_delete(path, passes=3):
    with open(path, "ba+", buffering=0) as delfile:
        length = delfile.tell()
    delfile.close()
    with open(path, "br+", buffering=0) as delfile:
        #print("Length of file:%s" % length)
        for i in range(passes):
            delfile.seek(0,0)
            delfile.write(os.urandom(length))
            #wait = input("Pass %s Complete" % i)
        #wait = input("All %s Passes Complete" % passes)
        delfile.seek(0)
        for x in range(length):
            delfile.write(b'\x00')
        #wait = input("Final Zero Pass Complete")
    os.remove(path) #So note here that the TRUE shred actually renames to file to all zeros with the length of the filename considered to thwart metadata filename collection, here I didn't really care to implement

def checkAESkeyinUSB(path):
    return os.path.exists(path)

def keyUpdate(path):
    USBAES_KEY = open(path, "r")
    data = USBAES_KEY.read()
    USBAES_KEY.close()

    f = open("AES_KEY.key", "w")
    f.write(data)
    f.close()

    secure_delete(path)

def checkKeyMatch(AESKEY):
    if isinstance(AESKEY, int):
        return 0 # Private key does not match
    else:
        return 1

def getKEY():
    if os.name == 'nt':
        PATH_TEMPLATE = '{}:\privateKEY.rsa'
        for drive in ascii_uppercase[:-24:-1]: # letters 'Z' down to 'D'
            file_path = PATH_TEMPLATE.format(drive)
            if os.path.exists(file_path):
                break
        else:
            return None

        if checkAESkeyinUSB(file_path[0]+':\AES_KEY.key') == True:
            keyUpdate(file_path[0]+':\AES_KEY.key')

        aeskeyf = open("AES_KEY.key", "r") # read AES key
        rsa_text = aeskeyf.read()
        aeskeyf.close()

        f = open(file_path, "r")
        key = f.read()
        Pri_key = RSA.importKey(key)
        cipher = PKCS1_cipher.new(Pri_key)
        AESKEY = cipher.decrypt(base64.b64decode(rsa_text), 0) # decrypt AES key using private key
        if checkKeyMatch(AESKEY) == 0:
            return "notmatch"
        return AESKEY.decode('utf-8')

    elif os.name == 'posix':
        file_path = '/media/'+getpass.getuser()+'/KEY/privateKEY.rsa'

        if not os.path.exists(file_path):
            return None

        if checkAESkeyinUSB('/media/'+getpass.getuser()+'/KEY/AES_KEY.key') == True:
            keyUpdate('/media/'+getpass.getuser()+'/KEY/AES_KEY.key')

        aeskeyf = open("AES_KEY.key", "r") # read AES key
        rsa_text = aeskeyf.read()
        aeskeyf.close()

        f = open(file_path, "r")
        key = f.read()
        Pri_key = RSA.importKey(key)
        cipher = PKCS1_cipher.new(Pri_key)
        AESKEY = cipher.decrypt(base64.b64decode(rsa_text), 0)  # decrypt AES key using private key
        if checkKeyMatch(AESKEY) == 0:
            return "notmatch"
        return AESKEY.decode('utf-8')
