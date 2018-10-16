import socket, threading, sys, ast
#import threading
#import sys
#ast - Library used for turning strings to arrays
from random import randint# Cypher key creation
try:
    from requests import get
except:
    print("[!] requests module not installed")

"""
https://docs.python.org/3.4/library/ast.html#ast.literal%5Feval # For string -> array
[+] = Added
[*] = Changed
[^] = Moved
[=] = No Changes
[x] = Deleted
[!] = Bugs
"""

PORT = 65530
#             [User] [Pass] [IP]  [Port]
UserNames = [["Nick", 1337, None, None]]
# Cypher key size
encryptionLength = 256





class Server:
    print("\n[*] Loading Sockets")
    connections = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    def __init__(self):
        print ("[*] Binding Address")
        self.sock.bind(("0.0.0.0", PORT))
        self.sock.listen(1)
        print("    Internal IP:",socket.gethostbyname(socket.gethostname()))
        try: # Doesn't intentionally run non-imported libraries
            print("    External IP:",(get('https://ipapi.co/ip/').text)) # [!] Hash out if requests is not installed
        except:
            pass
        print("    Port",PORT)
        print("[+] Reading Clients file")
        print("[*] Ready for connections")

    def is_prime(self, num, test_count): # Takes 
        if num == 1:
            return False
        if test_count >= num:
            test_count = num - 1
        for x in range(test_count):
            val = randint(1, num - 1)
            if pow(val, num-1, num) != 1:
                return False
        return True

    def generateBigPrime(self, n):
        found_prime = False
        while not found_prime:
            p = randint(2**(n-1), 2**n)
            if self.is_prime(p, 1000):
                return p

    def DiffyHellmanAssign(self): # Diffie-hellman key exchange
        publicBase = randint(100,1000)
        publicPrime = self.generateBigPrime(encryptionLength)
        privateKey = randint(10000000000000000000000000000000000000000000,100000000000000000000000000000000000000000000)
        sendKey = pow(publicBase, privateKey, publicPrime) # Key to send to client
        print()
        return publicBase, publicPrime, privateKey, sendKey
        

    def PrintUserNames():
        print("[=] Contents of UserNames:")
        for i in range(len(UserNames)):
            print("    ", end="")
            for x in range(4):
                print(UserNames[i][x], end=" ")
            print("\n")

    def CheckUsersFile(self, UserNames): # Reads logins from file
        file = open("Credential.txt","r")
        UserNames = file.readline()
        UserNames = ast.literal_eval(UserNames)
        return UserNames

    def AppendUsersFile(self, UserNames): # Writes logins to file
        file = open("Credential.txt","w")
        file.write(str(UserNames))
        file.close()

    def handler(self, c, a):
        publicBase, publicPrime, privateKey, sendKey = self.DiffyHellmanAssign()
        try:
            c.send(bytes((str(str(publicBase)+" "+str(publicPrime)+" "+str(sendKey))) ,"utf-8"))
            #print("-------SendKey:",sendKey)
            recvKey = c.recv(4096)
        except ConnectionResetError:
            Terminate = True
        recvKey = recvKey.decode("utf-8") # Client's key modded n' stuff
        cipherKey = pow(int(recvKey), int(privateKey), int(publicPrime))
        print("cipherKey:",cipherKey)
        
        





        # Once keys are exchanged, follow login attemps
        LoginAttempts=0
        while True:
            try:
                data = c.recv(1024)
            except ConnectionResetError:
                print("[x] Connection with",a[0],"was forcibly closed")
                Terminate = True
                break
            print ((data).decode("utf-8"),"-",a[0])
            data = data.decode("utf-8") # Decoded raw data
            
            if LoginAttempts >= 4:
                c.send(bytes("FinalRejection",'utf-8'))
                self.connections.remove(c)
                c.shutdown(socket.SHUT_RDWR) # Supposedly closes the socket
                c.close()
                print("[x] Connection with " + str(a[0]) + " Has been terminated")
                Terminate = True
                break
            else:
                Terminate = False
                
            if data[:3] == "HR-": # Checking for Hidden Registrations
                data = str(data[3:]) # Hidden so the data is not forwarded to all users
                data = data.split()
                UserNames.append([data[0],data[1],a[0], a[1]])
                self.AppendUsersFile(UserNames) # Appends the updated logins to file
            elif data[:3] == "HL-": # Checking for Hidden Logins
                data = str(data[3:])
                LoginAttempts+=1
                FoundUsername = False
                for i in range(len(UserNames)):
                    if int(data) == int(UserNames[i][1]):
                        c.send(bytes("Accepted",'utf-8'))
                        print("[*] Code Accepted from",a[0]+":"+str(a[1]))
                        UserNames[i][2] = (a[0])
                        UserNames[i][3] = (a[1])
                        FoundUsername = True
                        break
                if FoundUsername == False:
                    c.send(bytes("Rejected",'utf-8'))
                    print("[!] Code Rejected from",a[0]+":"+str(a[1]))
                else:
                    break
        while True:
            if Terminate == True: # Checks to see if invalid entries was hit, then kills thread
                break
            try:
                data = c.recv(1024)
            except ConnectionResetError:
                print("[x] Connection with " + str(a[0]) + " Has been terminated")
                break
            data = data.decode("utf-8") # Decoded raw data
            for i in range(len(UserNames)):
                if a[0] == UserNames[i][2] and a[1] == UserNames[i][3]: # Checks if port and ip are the same, then appends the username to a varuable
                    NickName = UserNames[i][0]
                else:
                    print("[!] Name and IP values not corresponding to stored values")
            print(a[0]+" ["+NickName+"]: "+str(data))
            for connection in self.connections:
                try:
                    connection.send((bytes((str("["+NickName + "] " + data)), 'utf-8'))) # Long string to append and encode message
                except ConnectionResetError:
                    print("[x] Connection with " + str(a[0]) + " Has been terminated")
                    break
            if not data:
                print("[x] " + str(a[0]) + ":" + str(a[1]),"Disconnected")
                self.connections.remove(c)
                c.close
                break
            
    def run(self):
        while True:
            try: # Only used to catch unexpected connection closures
                c, a = self.sock.accept()
                self.connections.append(c)
                print("[*] "+ str(a[0]) + ":" + str(a[1]), "Connected")
                cThread = threading.Thread(target=self.handler, args=(c, a))
                cThread.deamon = True
                cThread.start()
            except ConnectionResetError:
                print(a[0],"Closed connection unexpectedly")

                
if (len(sys.argv) > 1):
    pass
else:
    server = Server()
    #print(server.CheckUsersFile(UserNames)) # Displays current users in the users file
    UserNames = server.CheckUsersFile(UserNames)
    server.run()





























