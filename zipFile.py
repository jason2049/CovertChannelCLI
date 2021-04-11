import os

try: #auto install pyzipper
    import pyzipper
except ImportError:
    print("Trying to Install required module: pyzipper")
    os.system('pip3 install pyzipper')
    import pyzipper

def zipfile(filename, secret_password):
    with pyzipper.AESZipFile(filename + '.zip', 'w', compression=pyzipper.ZIP_LZMA) as zf:
        zf.setpassword(secret_password)
        zf.setencryption(pyzipper.WZ_AES, nbits = 256) #The strength of the AES encryption can be configure to be 128, 192 or 256 bits.
        zf.write(filename)