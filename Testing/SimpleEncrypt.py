import base64
import hashlib
from Crypto  import Random
from Crypto.Cipher import AES

class AESCipher(object):
    def __init__(self, key):
        self.key = self.hasher(key)

    def hasher(self, password):
        salt = b'\xdfU\xc1\xdf\xf9\xb30\x96' # This is the default salt i am using for client and server side
        return (  hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"), salt, 1000000)  )

    def encrypt(self, raw):
        b64 = base64.b64encode(raw.encode("utf-8")).decode("utf-8") # Turned to base64 because it stops a weird padding error in the module
        raw = self.pad(b64)                                         # That stops the £ symbol being sent
        rawbytes = bytes(raw,"utf-8")
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(rawbytes))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64decode(self.unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')).decode("utf-8")

    def pad(self,s): # Pads the string so that it complys with the AES 16 byte block size
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    def unpad(self, s): # Turns the 16 byte complyant string to a normal string
        return s[:-ord(s[len(s)-1:])]
import time
Cipher = AESCipher("This is a key")

import traceback
import binascii
#traceback.print_exc()
import os
def encryptor():
    totalsize = os.path.getsize("ProtonDark.ico")
    with open("ProtonDark.ico","rb") as f:
        with open("ProtonNew.ico","wb") as w:
            toencrypt = f.read(1024)
            hexed = binascii.hexlify(toencrypt).decode("utf-8")
            totalbytes = len(hexed)
            towrite = Cipher.encrypt(hexed)
            w.write(towrite)
            while totalbytes < totalsize:
                toencrypt = f.read(1024)
                hexed = binascii.hexlify(toencrypt).decode("utf-8")
                totalbytes+=len(hexed)
                print("Total So Far:",totalbytes)
                towrite = Cipher.encrypt(hexed)
                w.write(towrite)
def decryptor():
    with open("ProtonNew.ico","rb") as f:
        with open("ProtonRestored.ico","wb") as w:
            todecrypt = f.read(1024)
            hexed = binascii.unhexlify(todecrypt)
            totalbytes = len(hexed)
            w.write(hexed)
            while totalbytes < os.path.getsize("ProtonDark.ico"):
                todecrypt = f.read(1024)
                hexed = binascii.unhexlify(todecrypt)
                totalbytes = len(hexed)
                w.write(hexed)
