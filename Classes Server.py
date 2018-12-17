
# Importing modules
import socket, sys, os, time, sqlite3, select, threading, pickle, binascii, base64, hashlib, traceback
from random import randint
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

HOST = "0.0.0.0"
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

def Logger(orig_func): # For debugging the program, and also monitoring
    import logging
    from functools import wraps
    logging.basicConfig(filename = "{}.log".format(orig_func.__name__), level = logging.INFO)
    @wraps(orig_func)
    def wrapper(*args, **kwargs):
        logging.info("Ran with args: {}, and kwargs: {}".format(args, kwargs))
        return orig_func(*args, *kwargs)
    return wrapper

# Initialization of sockets
banner()

print("[*] Loading Sockets")
sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("[*] Binding address")
sock.bind((HOST, PORT))
try:
    print(str("[=] Internal IP: {}".format(getLocalIP())))
    print(str("[=] External IP: {}".format(get('https://ipapi.co/ip/').text))) # Non-standard library therefore try, except
except:
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
            if not args: # args are positional arguments for the sql statement
                db.execute(code) # Stop SQL injection by giving the option for args to be passed in
            else:
                db.execute(code, args) # Stops SQL injection with arguments
            data = db.fetchall() # Fetches the result of the query
            return data # Returns the data, if there is no data then the data will be an empty 2d array

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
        return False

    def AppendClientsDatabase(self, ip, port, nickname, password, accountType): # Complete
        self.CommandDB("INSERT INTO clients VALUES (?,?,?,?,?)",ip, port, nickname, password, accountType)

    def updateUser(self,User,**kwargs):
        for x in ("password","ip","port","accountType","nickname"):
            if x in kwargs:
                if x == "password":
                    kwargs["password"] = self.initialAES.hasher(kwargs["password"]) # Turns the plaintext password into a database usable password
                self.CommandDB("UPDATE clients SET {} = ? WHERE nickname = ?".format(x),kwargs[x],User)

    def allowedCreateAccount(self, ip, port, username): # Checks to see if the users ip and port are already in the database
        if self.CommandDB("SELECT * FROM clients WHERE ip = ? AND port = ?",ip, port):
            return False
        if self.CommandDB("SELECT * FROM clients WHERE nickname = ?",username):
            return False
        return True

    def CreateClientsTable(self):
        try: # Used because the database may already exist
            self.CommandDB("CREATE TABLE clients (ip text, port integer, nickname text, password text, accountType text, PRIMARY KEY (nickname))")
            # Primary key is username so the name is unique
            # Ip is text, not number, as it includes "."
            # Password is text as it will contain hex hashed password
            # AccountType will be "Admin" or "Standard"
            print("[+] Clients Database successfully created")
        except sqlite3.OperationalError: # Catches an exact error
            print("[=] Clients Database already created")

    def CreateBlockedTable(self):
        try: # Used because the database may already exist
            self.CommandDB("CREATE TABLE blockedUsers (relatingUser text NOT NULL,\
                            relationalUser text NOT NULL,\
                            type text NOT NULL,\
                            PRIMARY KEY (relatingUser, relationalUser),\
                            FOREIGN KEY (relatingUser) REFERENCES clients(nickname),\
                            FOREIGN KEY (relationalUser) REFERENCES clients(nickname))")
            # Sets up database with primary key as a composite of relatingUser and relationalUser so that there are no more than 1 Value
            # Foreign keys are used to link to the users to their respective accounts
            # type is either "Blocked" or "Unblocked"
            print("[+] Blocked Users Database successfully created")
        except  sqlite3.OperationalError: # Catches an exact error
            print("[=] Blocked Users Database already created")

    def PrintBlockedContents(self): # Prints all of blockedUsers table with headders
        data = self.CommandDB("SELECT * FROM blockedUsers")
        print("\n{:^16} | {:^16} | {:^7}\n".format("RelatingUser","RelationalUser","Type")+"-"*59)
        for row in data:
            print("{:^16} | {:^16} | {:^7}".format(row[0],row[1],row[2]))
        print()

    def EditBlockedDatabase(self, Relating, Relational, Type):
        if Relating == Relational:
            print("[!] {} tried blocking themself".format(Relating))
            return False
        for x in (Relating, Relational):
            if not self.CommandDB("SELECT nickname FROM clients WHERE nickname = ?",x):
                print("[=] {} tried blocking {} who is not in the database".format(Relating,x))
                return False # Returns false becasue the client is not in the table

        self.CommandDB("INSERT OR REPLACE INTO blockedUsers (relatingUser, relationalUser,type) VALUES (?,?,?)",Relating, Relational,Type)
        self.PrintCustomerContents()
        return True

    def isBlocked(self, Relating, Relational,Type="Blocked"):
        data = self.CommandDB("SELECT * FROM blockedUsers WHERE relatingUser = ? AND relationalUser = ? AND type = ?", Relating, Relational, Type)
        return True if data else False

    def currentlyBlockedUsers(self, Relating, Type="Blocked"):
        data = self.CommandDB("SELECT relationalUser FROM blockedUsers WHERE relatingUser = ? AND type = ?",Relating, Type)
        sterilizedOutput = []
        for x in data:
            sterilizedOutput.append(x[0])
        return sterilizedOutput

    def CreateMessageTable(self):
        try:
            self.CommandDB("CREATE TABLE messages (username text NOT NULL,\
                            message text NOT NULL,\
                            timedate text NOT NULL,\
                            FOREIGN KEY (username) REFERENCES clients(nickname))")
            print("[+] Messages Database successfully created")
        except sqlite3.OperationalError:
            print("[=] Messages Database already created")

    def AddMessage(self, user, message):
        if self.CommandDB("SELECT nickname FROM clients WHERE nickname = ?",user):
            self.CommandDB("INSERT INTO messages (username, message, timedate) VALUES (?,?,?)",user,message,time.asctime(time.localtime(time.time())))
        else:
            print("[!] User {}'s record cant be added to messages database, user not in clients database")

    def PrintMessagesContents(self):
        data = self.CommandDB("SELECT * FROM messages")
        print("\n{:^26} | {:^16} | {:^10}\n".format("Date and Time","Username","Message")+"-"*59)
        for row in data:
            print("{:^26} | {:^16} | {:^10}".format(row[2],row[0],row[1]))
        print()

    def dump(self, *args): # Made for Debugging, however mey be useful elsewhere
        for x in args:
            self.CommandDB("DELETE FROM {}".format(x))

DataBase = SQLDatabase("LoginCredentials.db")
os.remove("LoginCredentials.db")
DataBase.CreateClientsTable()
DataBase.CreateBlockedTable()
DataBase.CreateMessageTable()
DataBase.dump("clients","blockedUsers","messages") # Purely for testing (Stops duplicates)
DataBase.AppendClientsDatabase("1.3.3.7",666,"Nick1","bcc014de6fb06f937156515b8f36fb2a995c037f441862411160f4b48f1ad602","Standard")
DataBase.AppendClientsDatabase("1.3.3.7",666,"Nick","bcc014de6fb06f937156515b8f36fb2a995c037f441862411160f4b48f1ad602","Admin")
DataBase.PrintCustomerContents()
DataBase.PrintBlockedContents()
DataBase.PrintMessagesContents()

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
        self.loginAttempts = 0
        self.BlockedUsers = []

    @Logger
    def send(self, toSendToClient, cipher):
        toSendToClient = cipher.encrypt(toSendToClient)
        self.socket.send(toSendToClient)


    def recv(self, cipher):
        try:
            receaved = self.socket.recv(2048)
        except ConnectionResetError:
            try:
                print("[=] {} {} disconnected from the server - [{}:{}]".format("Admin" if self.database.isAdmin(self.credentials.username) else "Standard", self.credentials.username,self.ip, self.port))
            except:
                print("[=] Connection has been lost with {}:{}".format(self.ip,self.port))
            self.RemoveInstance(self)
            self.connectionlost = True
            return True
        receaved = receaved.decode("utf-8")
        try:
            decrypted = cipher.decrypt(receaved)
        except Exception as e:
            print("[!] Failed to decrypt message from {}:{}".format(self.ip,self.port))
            print("[!]         - {}".format(e))
            return True
        return (decrypted)

    def recvBytes(self, cipher):
        try:
            receaved = self.socket.recv(2048)
            decrypted = cipher.decrypt(receaved)
            return decrypted
        except ConnectionResetError:
            print("[=] Connection has been lost with {}:{}".format(self.ip,self.port))
            self.socket.close()
            counter = 0
            self.RemoveInstance(self)
            self.connectionlost = True
            return True

    def sendDiffieHellman(self):
        self.sendKey = pow(int(self.Base),int(self.Secret),int(self.Prime))
        self.socket.send(bytes(str(  (str(self.Base)+" "+str(self.Prime)+" "+str(self.sendKey))  ), 'utf-8'))     #
        # Send Base, Prime and SendKey to client. Structure using something like "Base Prime Key"
        self.recvkey = self.socket.recv(1024)
        self.recvkey = self.recvkey.decode("utf-8")
        self.DiffieHellman = pow(int(self.recvkey),int(self.Secret),int(self.Prime))
        return self.DiffieHellman

    def login(self):
        self.instance = self.recvBytes(self.initialAES)
        if self.loginAttempts > 3:
            print("[!] Max login attempts from {}:{}".format(self.ip,self.port))
            self.send("LAE",self.initialAES) # Login Attempts Exceeded
            self.RemoveInstance(self)
            self.connectionlost = True
            return False
        if self.instance == True or self.instance == False or self.instance == None or self.instance == 0:
            self.connectionlost = True
            print("[=] Connection has been lost with 'Not logged in' [{}:{}]".format(self.ip, self.port))
            self.RemoveInstance(self)
            return
        self.instance = bytes.fromhex(self.instance)
        self.credentials = pickle.loads(self.instance)
        if self.credentials.createaccount == True:
            if self.database.allowedCreateAccount(self.ip, self.port, self.credentials.username):
                self.database.AppendClientsDatabase(self.ip, self.port, self.credentials.username, self.credentials.password, "Standard")
                print("[+] User added to database:",self.ip, self.port, self.credentials.username, "Standard")
                self.send("ASC", self.initialAES) # Account successfully Created
                self.loggedIn = True
                return True
            else:
                print("[=] Sending Error")
                self.send("ERR-You have already made an account!", self.initialAES)
        elif self.database.checkPassword(self.credentials.username, self.credentials.password):
                self.loggedIn = True
                self.database.updateUser(self.credentials.username,ip=self.ip, port=self.port)
                self.send("SLI", self.initialAES)
                return True
        else:
            self.loggedIn = False
            self.send("ERR-You have entered an incorrect username or password!", self.initialAES)
            self.loginAttempts+=1
            return False

    def RemoveInstance(self, instance):
        counter=0
        for i in InstanceList:
            if instance == i:
                instance.socket.close()
                InstanceList.pop(counter)
                return
            counter+=1

    @Logger
    def DistributeMessage(self, message, sentfrom, accountType):
        print("[+] ["+sentfrom+"-"+accountType+"] "+message)
        itteration = len(InstanceList)
        delInstanceList = []
        for connecitons in reversed(InstanceList):
            if connecitons.loggedIn and not connecitons.sendingFiles and self.credentials.username not in connecitons.BlockedUsers:
                try:
                    connecitons.send("MSG|"+str(sentfrom)+"|"+str(accountType)+"|"+str(message), connecitons.initialAES)
                except:
                    print("[!] Couldn't send a message to "+connecitons.credentials.username +" [{}:{}]".format(connecitons.ip, connecitons.port))
                    print("[=]      - Removing {} from connected clients".format(connecitons.credentials.username))
                    self.RemoveInstance(connecitons) # Removes the instance from the list, therefore removing the connection
            itteration-=1

    def download(self, *args):
        self.sendingFiles = True
        size = int(args[0][1])
        filename = args[0][0]
        print("[+] File upload request from {}, filename: '{}' with size {} - [{}:{}]".format(self.credentials.username, filename, size, self.ip, self.port))
        if os.path.isfile("UserFiles\\"+filename):
            print("[!] File '{}' already exists  - {} [{}:{}]".format("UserFiles\\"+filename,self.credentials.username, self.ip, self.port))
            self.send("FAE",self.initialAES) # File Already Exists
            self.sendingFiles=False
            return
        else:
            print("Downloading file '{}' from {} [{}:{}]".format(filename, self.credentials.username, self.ip, self.port))
            self.send("STS",self.initialAES) # Safe to Send

        with open("UserFiles\\"+filename,"wb") as f:
            encFile=self.socket.recv(size)
            encFile = self.initialAES.decrypt(encFile)
            encFile = binascii.unhexlify(encFile)
            f.write(encFile)
        print("[+] Done downloading '{}' from {} [{}:{}]".format(filename,self.credentials.username,self.ip, self.port))
        self.sendingFiles = False

    def upload(self, *args):
        self.sendingFiles = True
        filename=args[0][0]
        pathfile = "UserFiles/"+str(filename)
        if os.path.isfile(pathfile):
            print("[^] Sending '{}' to {} [{}:{}]".format(pathfile,self.credentials.username,self.ip, self.port))
            self.send("FileDownload|"+str(filename)+"|"+str(os.path.getsize(pathfile)),self.initialAES)
            with open(pathfile,"rb") as f:
                toencrypt = binascii.hexlify(f.read(os.path.getsize(pathfile))).decode("utf-8")
            encrypted = self.initialAES.encrypt(toencrypt)
            time.sleep(1)
            self.send(str(len(encrypted)),self.initialAES)
            print("Sent length:",os.path.getsize(pathfile))
            self.socket.send(encrypted)
            print("[=] Done uploading '{}' to {} [{}:{}]".format(pathfile, self.credentials.username, self.ip, self.port))
        else:
            self.send("FNF", self.initialAES)
            print("[!] File '{}' not found [{} {}:{}]".format(pathfile, self.credentials.username, self.ip, self.port))
        self.sendingFiles = False

    def BlockUser(self, *args):
        usernames = args[0][0].split(" ")
        self.database.PrintBlockedContents()
        for x in usernames:
            if not self.database.EditBlockedDatabase(self.credentials.username,x,"Blocked"):
                print("CLient {} not in database".format(x))
                if self.credentials.username == x:
                    self.send("MSG|Server|Admin|You cannot block youself.",self.initialAES)
                else:
                    self.send("MSG|Server|Admin|There is no such user {}".format(x),self.initialAES)
            else:
                print("CLient {} in database".format(x))
                self.send("MSG|Server|Admin|User {} has been blocked".format(x),self.initialAES)
        self.BlockedUsers = self.database.currentlyBlockedUsers(self.credentials.username)

    def UnblockUser(self, *args):
        usernames = args[0][0].split(" ")
        self.database.PrintBlockedContents()
        for x in usernames:
            if not self.database.EditBlockedDatabase(self.credentials.username,x,"Unblocked"):
                if self.credentials.username == x:
                    self.send("MSG|Server|Admin|There is no reason to unblock youself",self.initialAES)
                else:
                    self.send("MSG|Server|Admin|There is no user {}".format(x),self.initialAES)
            else:
                self.send("MSG|Server|Admin|User {} has been unblocked".format(x), self.initialAES)
        self.BlockedUsers = self.database.currentlyBlockedUsers(self.credentials.username)

    def MessengerInterface(self):
        self.switcher = { # Key - [FunctionReference, Description, Example]
            "/Changepassword": [self.ChangeStandardPassword,"Changed the password of any user account","/ChangePassword [New Password]"],
            "/Logout": [self.Logout,"Logs the user out of their account","/Logout"],
            "/Changeusername": [self.ChangeUsername,"Change the username of current account","/Changeusername [NewUsername]"],
            "/Help": [self.ShowHelp,"Shows this help menu","/Help"], # A simple help message for the commands
            "Msg": [self.DistributeMessage,"Redistribute a message to other clients","No implimentation"],
            "Uploading": [self.download,"Actually downloads the file form the client, once the file is specified","You don't use this command as a client"],
            "/Upload": [self.sendUpload,"Upload a file to the server, use button or this command + filename","/Upload [FilePath]"], # The users upload is the servers download
            "/Download": [self.upload,"Download a file from the server","/Download [FileName]"], # The users download is the servers upload
            "/Block": [self.BlockUser,"Blocks a user from sending you messages","/Block [Username] [Optional aditional usernames]"],
            "/Unblock": [self.UnblockUser,"Allows a previously blocked user to send you messages","/Unblock [Username] [Optional aditional usernames]"]}

        if self.__class__ == Admins: # This allows admins to manipulate their extended privs inherited from Admins class
            # Key - [FunctionReference, Description, Example
            self.switcher["/Createadmin"] = [self.CreateAdminAccount,"Creates an admin account","/CreateAdmin [Username] [Password]"]
            self.switcher["/Ban"] = [self.BanUser,"Bans a user from the server","/Ban [Username]"]
            self.switcher["/Removeaccount"] = [self.RemoveAccount,"Deletes a users account","/RemoveAccount [Username]"]
            self.switcher["/Editaccount"] = [self.EditMember,"Edit an account","/EditAccount [Username] [AccountType]/[Password]=[Value]"]

        while not self.connectionlost and MainThreadClose == False: # While the client is connected run
            try:
                data = self.recv(self.initialAES)
                self.database.AddMessage(self.credentials.username,data)
                # self.database.PrintMessagesContents()
                if data[:3] == "MSG":
                    self.DistributeMessage(data[4:], self.credentials.username, "Standard" if not self.database.isAdmin(self.credentials.username) else "Admin")
                else:
                    edited = data.split("|")
                    try:
                        self.switcher[edited[0].title()][0](edited[1:])
                    except KeyError:
                        print("[!] Key error occured with data: '{}' from {} [{}:{}]".format(edited[0], self.credentials.username, self.ip, self.port))
                        self.send("Keyerror|{}".format(edited[0]),self.initialAES) # Make an error message here to be displayed on the users screen.
            except TypeError:
                self.connectionlost = True

    def ChangeStandardPassword(self,*args):
        pass
    def ChangeUsername(self,*args):
        pass
    def sendUpload(self, *args):
        pass
    def ShowHelp(self,*args):
        string=""
        self.send("MSG|Server|Admin|Commands for {}".format(self.__class__.__name__), self.initialAES)
        for x in self.switcher:
            if not x in ["Msg","Uploading"]: # Because the "MSG" is not a command, and shows backend structure too easily
                string+="{} {} {}\n".format(x, self.switcher[x][1],self.switcher[x][2])
        self.send("MSG|Server|Admin|{}".format(string),self.initialAES)
    def Logout(self,*args):
        self.send("Logout",self.initialAES) # Sends the disconnect message to the client so the client knows to change screen

    def handler(self): # This is run in a thread, one for each client
        self.sendDiffieHellman() # sets AES Key variable
        self.initialAES = AESCipher(hex(int(self.DiffieHellman))) # Creates the AES Cipher object using the key
        self.send("Encryption cipher working", self.initialAES) # Sends a test message to the client so the client can do a checkPassword
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
    def BanUser(self): # Possibly ban users from an ip address / Range
        pass
    def RemoveAccount(self, username):
        pass
    def CreateAdminAccount(self,*args):
        print(args)
        split = args[0][0].split(" ")
        if len(split) < 2:
            self.send("MSG|Server|Admin|Another argument is needed in the format '/Createadmin [Username] [Password]'",self.initialAES)
        else:
            print(split)
            if self.database.allowedCreateAccount:
                self.database.AppendClientsDatabase("N/A",0,split[0],self.initialAES.hasher(split[1]),"Admin")
                print("[+] Admin account {} has been created by {}".format(split[0],self.credentials.username))
                self.send("MSG|Server|Admin|Admin Account {} has been successfully created".format(split[0]),self.initialAES)
            else:
                print("[!] Admin account {} couldn't be made by {}".format(split[0],self.credentials.username))
                self.send("MSG|Server|Admin|Admin account {} could not be created, try a different username".format(split[0]),self.initialAES)

    def EditMember(self, username, **kwargs): # self.EditMember("Nick",ip="127.0.0.1") - This format using kwargs
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
        except socket.timeout: # Occurs every second, therefore no code to be run
            pass
    except KeyboardInterrupt:
        banner()
        print("[!] KeyboardInterrupt occured, quitting when all connecitons have dropped")
        MainThreadClose = True
        quit(0)
