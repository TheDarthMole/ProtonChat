import socket, threading, base64, hashlib, pickle, os, sys, binascii
from random import randint
from Crypto import Random
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

def sendMessage(cipher, message):
    encMessage = cipher.encrypt(message)
    try:
        sock.send(encMessage)
    except ConnectionResetError:
        messagebox.showerror("Message could not be sent","The connection to the server has been reset")

def recvMessage(cipher):
    receaved = sock.recv(7000)
    receaved = receaved.decode("utf-8")
    decrypted = cipher.decrypt(receaved)
    print("Receaved encrypted:",decrypted) # For Debugging
    return (decrypted)

def Sendfile(data, *files):
    file = data
    print(file)
    sendMessage(Cipher, os.path.getsize(file))
    with open(file,"rb") as f:
        bytesToSend = f.read(1024)
        bytesToSend = binascii.hexlify(bytesToSend).decode("utf-8")
        sendMessage(Cipher, bytesToSend)
        while bytesToSend != "":
            bytesToSend = f.read(1024)
            bytesToSend = (binascii.hexlify(bytesToSend).decode("utf-8"))
            sendMessage(Cipher, bytesToSend)
    print("Done!")

Cipher = AESCipher("This is a key")
HOST="127.0.0.1"
PORT = 65528
sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((HOST, PORT))
sock.listen(1)
print("Listening")
while 1:
    connection, ip = sock.accept()
    print("Accepted connection from {}:{}".format(ip[0],ip[1]))
    data = recvMessage(Cipher)
    print("Receaved:",data)
    Sendfile(data)
