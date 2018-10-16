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





import binascii

sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1",5000))
Cipher=AESCipher("SimpleKey")

def recvFile():
    filename=input("Enter the files name: ")
    sock.send(bytes(filename,"utf-8"))
    response = sock.recv(1024)
    response = response.decode("utf-8")
    print(response[:6])
    if response[:6] == "EXISTS":
        filesize=int((response[7:]))
        f = open("new_"+filename,"wb")
        data = sock.recv(5000)
        print(data)
        data = binascii.unhexlify(Cipher.decrypt(data))
        totalRecv=len(data)
        f.write(data)
        while totalRecv < filesize:
            print("Doing something")
            print(totalRecv, filesize)
            data = sock.recv(5000)
            data = binascii.unhexlify(Cipher.decrypt(data))
            totalRecv += len(data)
            f.write(data)
        print("Done!")
    else:
        print(response[7:])
        print("File does not exist")
recvFile()




































