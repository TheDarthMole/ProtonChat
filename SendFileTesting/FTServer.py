import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import base64, socket
class AESCipher:
    def __init__(self, key):
        self.key = self.hasher(key)

    def hasher(self, password): # Type can be either "string" or "bytes"
        salt = b'\xdfU\xc1\xdf\xf9\xb30\x96' # This is the default salt i am using for client and server side
        return (  hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"), salt, 100000)  )

    def encrypt(self, raw):
        raw = self.pad(raw)
        rawbytes = bytes(raw,"utf-8")
        iv = Random.new().read(AES.block_size)
        #print("IV:",iv)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(rawbytes))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')


    def pad(self,s): # Pads the string so that it complys with the AES 16 byte block size
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    def unpad(self, s): # Turns the 16 byte complyant string to a normal string
        return s[:-ord(s[len(s)-1:])]


import os, binascii
HOST="127.0.0.1"
PORT=5000
Cipher = AESCipher("SimpleKey")
sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((HOST, PORT))
sock.listen(1)

def sendFile():
    filename = con.recv(1024)
    if os.path.isfile(filename):
        filename = filename.decode("utf-8")
        print(filename)
        con.send(str("EXISTS "+str(os.path.getsize(filename))).encode("utf-8"))
        with open(filename,"rb") as f:
            bytesToSend = f.read(1024)
            print("Hexed:",binascii.hexlify(bytesToSend).decode("utf-8"))
            bytesToSend = binascii.hexlify(bytesToSend).decode("utf-8")
            con.send(Cipher.encrypt(bytesToSend))
            while bytesToSend != "":
                print("Sending!")
                bytesToSend = f.read(1024)
                bytesToSend = Cipher.encrypt(binascii.hexlify(bytesToSend).decode("utf-8"))
                con.send(bytesToSend)
    else:
        con.send(b"FNF")
print("Acceptint connecitons")
con, ip = sock.accept()
print("Connected!")
sendFile()
