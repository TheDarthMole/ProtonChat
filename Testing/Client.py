import socket
import threading
import time
from random import randint

"""
[+] = Added
[*] = Changed
[^] = Moved
[=] = No Changes
[x] = Deleted
[!] = Bugs
"""

address = "192.168.233.1"
port = 65530
BreakConnection = False
# Diffie-hellman key declerations
publicPrime = None
publicBase = None
privateKey = None
cipherKey = None

class Client:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print ("[*] Socket Setup")

    def sendMessage(self):
        while True:
            if BreakConnection == True:
                break
            try:
                self.sock.send((bytes(input(""), 'utf-8')))
            except ConnectionResetError:
                pass
            time.sleep(0.3)

    def DiffyHellman(self, diffieHellman): # Diffie-hellman key exchange
        diffieHellman = diffieHellman.split(" ")
        publicBase, publicPrime, recvKey = diffieHellman
        privateKey = randint(10000000000000000000000000000000000000000000,100000000000000000000000000000000000000000000)
        sendKey = pow(int(publicBase), int(privateKey), int(publicPrime))
        try:
            self.sock.send(bytes(str(sendKey),"utf-8"))
            cipherKey = pow(int(recvKey), int(privateKey), int(publicPrime))
            print("\ncipherKey:",cipherKey)
        except ConnectionResetError:
            print("[x] Connection with",address+":"+str(port),"was actively closed")
            BreakConnection = True
        
        

    def CodeChecking(self, BreakConnection):
        # Code entry
        code = 0
        newaccount = input("[+] Would you like to make a new account? (Y/N) ")
        while True:
            if newaccount.upper() == "Y":
                setname = input("[+] Enter you're New Username: ")
                while True:
                    setcode = input("[+] Enter you're New Code: ")
                    if setcode.isdigit():
                        newaccount = "N"
                        break
                    else:
                        print("[!] Code is not an interger value")
                try:
                    self.sock.send(bytes(("HR-"+str(setname)+" "+str(setcode)),'utf-8'))
                    print("[+] Account successfully created")
                except ConnectionResetError:
                    print("[x] Connection with",address+":"+str(port),"was actively closed")
            else:
                code = input("[+] Enter you're login code: ")
                try:
                    self.sock.send(bytes(("HL-"+str(code)),'utf-8')) # Appends "HL-" at beginning
                    codecheck = self.sock.recv(1024)                # to denote hidden from chat log
                except ConnectionResetError:
                    print("[x] Connection with",address+":"+str(port),"was actively closed")
                    break
                if codecheck.decode('utf-8') == "Accepted":
                    print("[*] Successful Login")
                    break
                elif codecheck.decode('utf-8') == "FinalRejection":
                    print("[x] Final Rejection")
                    exit(0)
                elif codecheck.decode('utf-8') == "Rejection":
                    print("[!] Rejected Code")
        return BreakConnection


    def __init__(self, address):
        BreakConnection = False
        try:
            self.sock.connect((address, port))
            print ("[*] Client Connected to {}:{}".format(address, port))
        except TimeoutError:
            print("[!] The host didn't respond, server could be down etc.")
            return

        try:
            diffieHellman = self.sock.recv(4096)
            diffieHellman = diffieHellman.decode("utf-8")
            self.DiffyHellman(diffieHellman)
        except ConnectionResetError:
            BreakConnection = True
            print("[x] Connection with",address+":"+str(port),"was actively closed")
            
            
        
            
        if not BreakConnection:
            BreakConnection = self.CodeChecking(self) # Calls Code checking function ( Login )
            iThread = threading.Thread(target=self.sendMessage)
            iThread.deamon = True
            iThread.start()

            while True:
                try:
                    data = self.sock.recv(1024)
                    if not data:
                        break
                    print(str(data, 'utf-8'))
                except ConnectionResetError:
                    BreakConnection = True
                    print("[x] Connection with",address+":"+str(port),"was actively closed")
                    break

client = Client(address)
