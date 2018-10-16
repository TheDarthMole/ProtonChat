
# Importing modules
import socket, sys, os, time, sqlite3, select, threading, pickle, binascii
from random import randint
import base64, hashlib, traceback
try:
    from Crypto import Random
    from Crypto.Cipher import AES
except ImportError:
    print("[!] pyCrypto module not installed! Install using in cmd 'py -m pip install pyCrypto' ")
    exit(1)

try:
    from requests import get # Non-standard library
except ImportError:
    print("[!] requests module not installed, however it is not necessary")

# Declare public variables and initialize
HOST = "127.0.0.1"
ClientMax = 10
PORT = 65528

"""
[+] = Added
[*] = Changed
[^] = Moved
[=] = No Changes
[x] = Deleted
[!] = Bugs
"""

# External function declerations

def banner():
    print("  _____           _")
    print(" |  __ \         | |")
    print(" | |__) | __ ___ | |_ ___  _ __")
    print(" |  ___/ '__/ _ \| __/ _ \| '_ \ ")
    print(" | |   | | | (_) | || (_) | | | |")
    print(" |_|   |_|  \___/ \__\___/|_| |_|")
    print(" Server v 1.0 | Nicholas Ruffles")
    print("      OCR Computer Science\n")

def getLocalIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80)) # 8.8.8.8 is Googles DNS server; its an ip not going to change anytime soon
    localip=s.getsockname()[0]
    s.close()
    return localip

# Initialization of sockets
banner()

print("[*] Loading Sockets")
sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("[*] Binding address")
sock.bind((HOST, PORT))
try:
    print(str(str("[=] Internal IP: {}".format(getLocalIP()))))
    print(str("[=] External IP: {}".format(get('https://ipapi.co/ip/').text))) # Non-standard library therefore try, except
except ModuleNotFoundError:
    pass
print(str("[=] Port: {}".format(PORT)))
sock.settimeout(1.0)
sock.listen(ClientMax)

print("[*] Listening for a max of "+str(ClientMax)+" clients")
InstanceList = []

# Class declerations

class SQLDatabase:
    def __init__(self, DBFileName):
        self.dbfile = DBFileName

    def CommandDB(self, code, *args): # Semi-universal SQL command executor, however allows SQL injection when variable entered
        with sqlite3.connect(self.dbfile) as conn:
            db=conn.cursor()
            if not args:
                db.execute(code) # Tries to stop SQL injection by giving the option for args to be passed in
            else:
                db.execute(code, args)
            data = db.fetchall()
            return data

    def isAdmin(self, username):
        data = self.CommandDB("SELECT accountType FROM clients WHERE nickname = ?",username)
        if str(data[0][0]) == "Admin":
            return True
        return False

    def PrintCustomerContents(self): # Complete
        data = self.CommandDB("SELECT * FROM clients")
        print("\n{:^18} | {:^10} | {:^18} | {:^10} | {:^10}\n".format("IP","PORT","NickName","AccType","Password")+"-"*132)
        for row in data:
            print("{:^18} | {:^10} | {:^18} | {:^10} | {:^10}".format(row[0],row[1],row[2],row[4], row[3]))
        print()

    def checkPassword(self, username, password):
        data = self.CommandDB("SELECT password FROM clients WHERE nickname = ?", username)
        if len(data) == 1 and data[0][0] == password:
            return True
        else:
            return False

    def AppendDatabase(self, ip, port, nickname, password, accountType): # Complete
        with sqlite3.connect(self.dbfile) as conn:
            db=conn.cursor()
            db.execute("INSERT INTO clients VALUES (?,?,?,?,?)",(ip, port, nickname, password, accountType))

    def UpdatePortIP(ip, port, username):
        self.CommandDB("UPDATE clients SET ip = ?, port = ? WHERE nickname = ?", ip, port, username)

    def allowedCreateAccount(self, ip, port, username): # Checks to see if the users ip and port are already in the database
        data = self.CommandDB("SELECT * FROM clients WHERE ip = ? AND port = ?",ip, port)
        if data:
            return False
        data = self.CommandDB("SELECT * FROM clients WHERE nickname = ?",username)
        if data:
            return False
        return True

    def CreateClientsTable(self):
        try:
            self.CommandDB("CREATE TABLE clients (ip text, port integer, nickname text, password text, accountType text, PRIMARY KEY (nickname))")
            print("[+] Database successfully created")
        except sqlite3.OperationalError:
            print("[=] Database already created")

    def dump(self):
        self.CommandDB("DELETE FROM clients")

DataBase = SQLDatabase("LoginCredentials.db")
DataBase.CreateClientsTable()
DataBase.dump() # Purely for testing (Stops duplicates)
DataBase.AppendDatabase("1.3.3.7",666,"Nick1","bcc014de6fb06f937156515b8f36fb2a995c037f441862411160f4b48f1ad602","Standard")
DataBase.AppendDatabase("1.3.3.7",666,"Nick","bcc014de6fb06f937156515b8f36fb2a995c037f441862411160f4b48f1ad602","Admin")
DataBase.PrintCustomerContents()


class UserCredentials:
    def __init__(self, username, password, createaccount):
        self.username = username
        self.password = password
        self.createaccount = createaccount

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

class Members:
    def __init__(self, connection, ip, port):
        self.ip = ip
        self.port = port
        self.socket = connection
        self.nickname = None
        self.code = None
        self.DiffieHellman = None
        self.Prime = """529204664323527979712946862439191145311982207310489934007\
464831218031464077205916042049447783375725379654966060134\
402111426034716246754987996475613641992085506553374675640\
6145751654070887955334806643930700832559492186669690829"""
        self.Prime = int(self.Prime)
        self.Base = randint(2,3)
        self.Secret = randint(2**100, 2**150)
        self.initialAES = None
        self.finalAES = None
        self.database = SQLDatabase("LoginCredentials.db")
        self.connectionlost = False
        self.loggedIn = False
        self.sendingFiles = False

    def send(self, toSendToClient, cipher):
        toSendToClient = cipher.encrypt(toSendToClient)
        self.socket.send(toSendToClient)

    def recv(self, cipher):
        try:
            receaved = self.socket.recv(2048)
        except ConnectionResetError:
            print("[*] Connection has been lost with {}:{}".format(self.ip,self.port))
            self.connectionlost = True
            return True
        receaved = receaved.decode("utf-8")
        try:
            decrypted = cipher.decrypt(receaved)
        except Exception as e:
            print("[!] Failed to decrypt message from {}:{}".format(self.ip,self.port))
            print(e)
            return True
        return (decrypted)

    def recvBytes(self, cipher):
        try:
            receaved = self.socket.recv(2048)
            decrypted = cipher.decrypt(receaved)
            return decrypted
        except ConnectionResetError:
            print("[*] Connection has been lost with {}:{}".format(self.ip,self.port))
            self.connectionlost = True
            return True

    def sendDiffieHellman(self):
        #sendKey = pow(int(publicBase), int(privateKey), int(publicPrime))
        self.sendKey = pow(int(self.Base),int(self.Secret),int(self.Prime))
        self.socket.send(bytes(str(  (str(self.Base)+" "+str(self.Prime)+" "+str(self.sendKey))  ), 'utf-8'))     #
        # Send Base, Prime and SendKey to client. Structure using something like "Base Prime Key"
        self.recvkey = self.socket.recv(1024)
        self.recvkey = self.recvkey.decode("utf-8")
        self.DiffieHellman = pow(int(self.recvkey),int(self.Secret),int(self.Prime))
        return self.DiffieHellman

    def login(self):
        self.instance = self.recvBytes(self.initialAES)
        if self.instance == True or self.instance == False or self.instance == None or self.instance == 0:
            self.connectionlost = True
            print("[*] Connection has been lost with 'Not logged in' [{}:{}]".format(self.ip, self.port))
            return
        self.instance = bytes.fromhex(self.instance)
        self.credentials = pickle.loads(self.instance)
        if self.credentials.createaccount == True:
            if self.database.allowedCreateAccount(self.ip, self.port, self.credentials.username):
                self.database.AppendDatabase(self.ip, self.port, self.credentials.username, self.credentials.password, "Standard")
                print("[+] User added to database:",self.ip, self.port, self.credentials.username, "Standard")
                # self.database.PrintCustomerContents()
                self.send("ASC", self.initialAES) # Account successfully Created
                self.loggedIn = True
                return True
            else:
                print("[=] Sending Error")
                self.send("ERR-You have already made an account!", self.initialAES)
        elif self.database.checkPassword(self.credentials.username, self.credentials.password):
                self.loggedIn = True
                self.send("SLI", self.initialAES)
                return True
        else:
            self.loggedIn = False
            self.send("ERR-You have entered an incorrect username or password!", self.initialAES)
            return False

    def DistributeMessage(self, message, sentfrom, accountType):
        print("["+sentfrom+"-"+accountType+"] "+message)
        for connecitons in InstanceList:
            if connecitons.loggedIn == True and not connecitons.sendingFiles:
                try:
                    connecitons.send("MSG|"+str(sentfrom)+"|"+str(accountType)+"|"+str(message), connecitons.initialAES)
                except:
                    traceback.print_exc()
                    print("[!] couldn't send a message to "+connecitons.credentials.username +" [{}:{}]".format(connecitons.ip, connecitons.port))

    def download(self):
        self.sendingFiles = True
        self.sendingFiles = False
        pass
    def upload(self, *args):
        self.sendingFiles = True
        print(args)
        filename=args[0][0]
        pathfile = "UserFiles/"+str(filename)
        print(os.path.isfile(pathfile))
        if os.path.isfile(pathfile):
            print(pathfile)
            print("[^] Sending '{}' to {} [{}:{}]".format(pathfile,self.credentials.username,self.ip, self.port))
            self.send("FileDownload|"+str(filename)+"|"+str(os.path.getsize(pathfile)),self.initialAES)
            with open(filename,"rb") as f:
                bytesToSend = f.read(1024)
                print("Hexed:",binascii.hexlify(bytesToSend).decode("utf-8"))
                bytesToSend = binascii.hexlify(bytesToSend).decode("utf-8")
                self.send(bytesToSend,self.initialAES)
                while bytesToSend != "":
                    
                    bytesToSend = f.read(1024)
                    bytesToSend = (binascii.hexlify(bytesToSend).decode("utf-8"))
                    print("Sending:",bytesToSend)
                    self.send(bytesToSend, self.initialAES)
                print("Done!")
        else:
            self.send("FNF", self.initialAES)
        self.sendingFiles = False

    def MessengerInterface(self):
        self.switcher = {
            "/ChangePassword": self.ChangeStandardPassword,
            "/Logout": self.Logout,
            "/ChangeUsername": self.ChangeUsername,
            "/Help": self.ShowHelp,
            "MSG": self.DistributeMessage,
            "/Upload": self.download,
            "/Download": self.upload}
        if self.__class__ == Admins: # This allows admins to manipulate their extended privs inherited from Admins class
            self.switcher = {
                "/Changepassword": self.ChangeStandardPassword,
                "/Logout": self.Logout,
                "/Changeusername": self.ChangeUsername,
                "/Help": self.ShowHelpAdmin,
                "Msg": self.DistributeMessage,
                "/Upload": self.download,
                "/Download":self.upload,
                "/Createadmin": self.CreateAdminAccount,
                "/Ban":self.BanUser,
                "/Removeaccount":self.RemoveAccount,
                "/Editaccount":self.EditMember}
        while not self.connectionlost and MainThreadClose == False: # While the client is connected run
            try:
                data = self.recv(self.initialAES)
                if data[:3] == "MSG":
                    self.DistributeMessage(data[4:], self.credentials.username, "Standard" if not self.database.isAdmin(self.credentials.username) else "Admin")
                else:
                    edited = data.split("|")
                    try:
                        self.switcher[edited[0].title()](edited[1:])
                    except KeyError:
                        self.send("") # Make an error message here to be displayed on the users screen.
            except TypeError:
                self.connectionlost = True
                pass
    def ChangeStandardPassword(self,*args):
        pass
    def ChangeUsername(self,*args):
        pass
    def ShowHelp(self,*args):
        pass
    def Logout(self,*args):
        pass

    def handler(self): # This is run in a thread, one for each client
        self.sendDiffieHellman()
        self.initialAES = AESCipher(hex(int(self.DiffieHellman)))
        self.send("Encryption cipher working", self.initialAES)
        self.loggedIn=False
        self.contunue = self.login()
        while not self.contunue and self.connectionlost == False:
            self.contunue = self.login() # Makes sure the user is logged in to an account
        if self.database.isAdmin(self.credentials.username):
            self.__class__ = Admins
            print("[+] {} logged in as an Admin from {}:{}".format(self.credentials.username, self.ip, self.port))
        else:
            print("[+] {} logged in as a Member from {}:{}".format(self.credentials.username, self.ip, self.port))
        self.MessengerInterface()

class Admins(Members):
    def __init__(self, ip, port, nickname, password):
        super().__init__(ip, port, nickname, password)
    def ShowHelpAdmin(self):
        pass
    def adminHandler(self):
        pass
    def BanUser(self): # Possibly ban users from an ip address / Range
        pass
    def RemoveAccount(self):
        pass
    def CreateAdminAccount(self, nickname, password):
        pass
    def EditMember(self):
        pass

distributeThreads = []
MainThreadClose = False
print("[*] Searching for connections")
while 1: # Stuff here for accepting connections # Leading to create a seperate thread for connected clients
    try: # Nesting "try" so that the output looks cleaner when KeyboardInterrupt occurs (Stops multiple errors displaying)
        try:
            connection, ip = sock.accept()
            InstanceList.append(Members(connection,ip[0], ip[1]))
            print("[+] "+str(ip[0])+":"+str(ip[1])+" Connected!")
            distributeThreads.append(threading.Thread(target=InstanceList[len(InstanceList)-1].handler))
            distributeThreads[len(distributeThreads)-1].deamon = True
            distributeThreads[len(distributeThreads)-1].start()

        except socket.timeout:
            pass
    except KeyboardInterrupt:
        banner()
        print("[!] KeyboardInterrupt occured, quitting when all connecitons have dropped")
        MainThreadClose = True
        quit(0)
