# Importing modules
import socket, sys, os, time, sqlite3, select, threading, pickle, binascii, base64, hashlib, traceback
from random import randint

def installModule(package):
    import subprocess
    import sys
    try:
        subprocess.call([sys.executable, "-m", "pip", "install", package])
    except:
        print("[!] Failed to install {}".format(package))

installModule("pycryptodome")
installModule("requests")

try:
    from Crypto import Random
    from Crypto.Cipher import AES
except ImportError:
    print("[!] pyCrypto module not installed! Install using in cmd 'py -m pip install pyCrypto' ")
    exit(1)
try:
    from requests import get # Non-standard library
except ImportError:
    print("[!] requests module not installed, installing it now")
    installModule()

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
        open(DBFileName,"a")
        # Creates the file if not already made

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
        # Queries database see if user is in database, then gets the "accountType"
        if str(data[0][0]) == "Admin": # If if's an admin, return true
            return True
        return False # If the previous statement is false then this is run

    def PrintCustomerContents(self): # Complete
        data = self.CommandDB("SELECT * FROM clients")
        # Data is all of the enteries from the database in a 2d array
        print("\n{:^18} | {:^10} | {:^18} | {:^10} | {:^10}\n".format("IP","PORT","NickName","AccType","Password")+"-"*132)
        # Formatting for display purposes
        for row in data:
            print("{:^18} | {:^10} | {:^18} | {:^10} | {:^10}".format(row[0],row[1],row[2],row[4], row[3]))
        # Loops through the data and prints it in a nice format
        # This means that no thrid party software is needed
        # So it can be run on a terminal easily.
        print()

    def checkPassword(self, username, password):
        data = self.CommandDB("SELECT password FROM clients WHERE nickname = ?", username)
        # Returns the password from the database with the selected user
        if len(data) == 1 and data[0][0] == password:
            return True
        # Returns true if the passwords are equvivlent
        # Else it returns false
        return False

    def AppendClientsDatabase(self, ip, port, nickname, password, accountType): # Complete
        self.CommandDB("INSERT INTO clients VALUES (?,?,?,?,?)",ip, port, nickname, password, accountType)
        # Adds a client to the database with passed in data

    def updateUser(self,User,**kwargs):
        # kwargs can be used to update the users table
        # Using the key as the database field name and
        # The data to update the existing data
        # As there are many possible enteries for kwargs
        # Checks are done to make sure they correspond to
        # Field names
        for x in ("password","ip","port","accountType","nickname"):
            if x in kwargs:
                if x == "password":
                    kwargs["password"] = self.initialAES.hasher(kwargs["password"]) # Turns the plaintext password into a database usable password
                self.CommandDB("UPDATE clients SET {} = ? WHERE nickname = ?".format(x),kwargs[x],User)

    def allowedCreateAccount(self, ip, port, username): # Checks to see if the users ip and port are already in the database
        if self.CommandDB("SELECT * FROM clients WHERE ip = ? AND port = ?",ip, port):
            return False
        # Returns false if there is already a users ip is already in the database
        if self.CommandDB("SELECT * FROM clients WHERE nickname = ?",username):
            return False
        # Returns false if there is already an existing user with that name in the database
        return True
        # Returns true if there are no conflictions

    def CreateClientsTable(self):
        try: # Used because the database may already exist
            self.CommandDB("CREATE TABLE clients (ip text NOT NULL,\
                            port integer NOT NULL,\
                            nickname text NOT NULL,\
                            password text NOT NULL,\
                            accountType text NOT NULL,\
                            PRIMARY KEY (nickname))")
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
            # Sets up database with primary key as a composite of relatingUser
            # and relationalUser so that there are no more than 1 Value
            # Foreign keys are used to link to the users to their respective accounts
            # type is either "Blocked" or "Unblocked"
            print("[+] Blocked Users Database successfully created")
        except  sqlite3.OperationalError: # Catches an exact error
            print("[=] Blocked Users Database already created")

    def PrintBlockedContents(self): # Prints all of blockedUsers table with headders
        data = self.CommandDB("SELECT * FROM blockedUsers")
        # Gets all data from blockedUsers tale in a 2d array format
        print("\n{:^16} | {:^16} | {:^7}\n".format("RelatingUser","RelationalUser","Type")+"-"*59)
        # Displays collumn headders in a readable format
        for row in data:
            print("{:^16} | {:^16} | {:^7}".format(row[0],row[1],row[2]))
        # Displays the data in different formatted rows
        print()

    def EditBlockedDatabase(self, Relating, Relational, Type):
        if Relating == Relational:
            print("[!] {} tried blocking themself".format(Relating))
            return False
        # Checks if the user is trying to block themselves
        for x in (Relating, Relational):
            if not self.CommandDB("SELECT nickname FROM clients WHERE nickname = ?",x):
                print("[=] {} tried blocking {} who is not in the database".format(Relating,x))
                return False # Returns false becasue the client is not in the table
        # If either users are not in the database then return false
        self.CommandDB("INSERT OR REPLACE INTO blockedUsers (relatingUser, relationalUser,type) VALUES (?,?,?)",Relating, Relational,Type)
        # Inserts or updates the existing record to contain the correct data
        self.PrintCustomerContents()
        # Displays the contents of the blocked table
        # (This is not necessary however there is no other easier way to show the contents)
        return True
        # If checks succeed then return True

    def isBlocked(self, Relating, Relational,Type="Blocked"):
        data = self.CommandDB("SELECT * FROM blockedUsers WHERE relatingUser = ? AND relationalUser = ? AND type = ?", Relating, Relational, Type)
        # Selects the data from the database where an exact criteria is met
        return True if data else False
        # If there is an existing entry in the database then return true, else return false

    def currentlyBlockedUsers(self, Relating, Type="Blocked"):
        data = self.CommandDB("SELECT relationalUser FROM blockedUsers WHERE relatingUser = ? AND type = ?",Relating, Type)
        # Retrieves data from database
        sterilizedOutput = []
        for x in data:
            sterilizedOutput.append(x[0])
        return sterilizedOutput
        # Returns the entire amount of people a user has blocked in array form

    def CreateMessageTable(self):
        try: # Used because the database may already exist
            self.CommandDB("CREATE TABLE messages (username text NOT NULL,\
                            message text NOT NULL,\
                            timedate text NOT NULL,\
                            FOREIGN KEY (username) REFERENCES clients(nickname))")
            # Creates the table with foreign key as the username of the client
            # Timedate is text as it needs to contain more information than timedate type
            # Message contains the message that the user sent, including metadata
            # Validation makes sure that the data cannot be empty
            print("[+] Messages Database successfully created")
        except sqlite3.OperationalError: # Catches an exact error
            print("[=] Messages Database already created")

    def AddMessage(self, user, message):
        if self.CommandDB("SELECT nickname FROM clients WHERE nickname = ?",user):
            # If the user is in the database
            self.CommandDB("INSERT INTO messages (username, message, timedate) VALUES (?,?,?)",user,message,time.asctime(time.localtime(time.time())))
            # Insert a message into the table, adding the username and the time of the message being sent (including seconds)
        else:
            print("[!] User {}'s record cant be added to messages database, user not in clients database")
            # A message to display that the user isn't in the database

    def PrintMessagesContents(self):
        data = self.CommandDB("SELECT * FROM messages")
        print("\n{:^26} | {:^16} | {:^10}\n".format("Date and Time","Username","Message")+"-"*59)
        for row in data:
            print("{:^26} | {:^16} | {:^10}".format(row[2],row[0],row[1]))
        print()

    def dump(self, *args): # Made for Debugging, however mey be useful elsewhere
        for x in args:
            self.CommandDB("DELETE FROM {}".format(x))
        # Simply deletes all the tables that are passed in as args

DataBase = SQLDatabase("LoginCredentials.db")
# os.remove("LoginCredentials.db")
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
        # Sets up the parameters as instance variables

class AESCipher(object):
    def __init__(self, key):
        self.key = self.hasher(key)
        # Hashes a value and uses it as the cipher

    def hasher(self, password):
        salt = b'\xdfU\xc1\xdf\xf9\xb30\x96' # This is the default salt i am using for client and server side
        # This is the default salt i am using for client and server side
        # Theoretically this should be random for each user and stored in the database
        return (  hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"), salt, 1000000)  )
        # Returns the hashed password using PBKDF2 HMAC

    def encrypt(self, raw):
        b64 = base64.b64encode(raw.encode("utf-8")).decode("utf-8") # Turned to base64 because it stops a weird padding error in the module
        # Base 64 encoding using "UTF-8" encoding
        raw = self.pad(b64)                                         # That stops the £ symbol being sent
        # Padded so that it is a multiple of 16 (Block cipher length)
        rawbytes = bytes(raw,"utf-8")
        iv = Random.new().read(AES.block_size)
        # Random IV to make the ciphertext random
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        # New cipher instance using the random IV and the encryption key
        return base64.b64encode(iv + cipher.encrypt(rawbytes))
        # Returns the data encrypted and in base4 format

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        # Splits up the IV and the data
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        # Creats the cipher to decrypt the data
        return base64.b64decode(self.unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')).decode("utf-8")
        # Returns the decrypted data as a plaintext string

    def pad(self,s): # Pads the string so that it complys with the AES 16 byte block size
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)
        # Pads the data to a size of multiple 16

    def unpad(self, s): # Turns the 16 byte complyant string to a normal string
        return s[:-ord(s[len(s)-1:])]
        # Removes the padding from a string

class Members:
    def __init__(self, connection, ip, port):
        self.ip = ip
        self.port = port
        self.socket = connection
        self.DiffieHellman = None
        self.Prime = """529204664323527979712946862439191145311982207310489934007\
464831218031464077205916042049447783375725379654966060134\
402111426034716246754987996475613641992085506553374675640\
6145751654070887955334806643930700832559492186669690829"""
        # Large prime number to use for the diffie-hellman
        self.Prime = int(self.Prime)
        self.Base = randint(2,3)
        self.Secret = randint(2**100, 2**150)
        # Random numbers for diffie-hellman key exchange
        self.initialAES = None
        self.database = SQLDatabase("LoginCredentials.db")
        # Assigns a database instance per connected user
        self.connectionlost = False
        self.loggedIn = False
        self.sendingFiles = False
        self.loginAttempts = 0
        self.BlockedUsers = []
        # Setting  up instance variables

    @Logger # Logger is used to make sure data is stored in the case of a crash
    def send(self, toSendToClient, cipher):
        toSendToClient = cipher.encrypt(toSendToClient)
        # Encrypts the data using the cipher passed into the subroutine
        self.socket.send(toSendToClient)
        # Sends the data to the client


    def recv(self, cipher):
        try: # Used because the socket may be disconnected
            receaved = self.socket.recv(2048)
            # Recieves data from the client
        except ConnectionResetError:
            # Catches an error if the client has disconnected
            try:
                # Embedded try becuse the user may not be logged in yet
                print("[=] {} {} disconnected from the server - [{}:{}]".format("Admin" if self.database.isAdmin(self.credentials.username) else "Standard", self.credentials.username,self.ip, self.port))
            except:
                print("[=] Connection has been lost with {}:{}".format(self.ip,self.port))
                # Logs the user has lost connection and they where not logged in
            self.RemoveInstance(self)
            # Removes the connection from the server if the client has disconnected
            self.connectionlost = True
            return True
        receaved = receaved.decode("utf-8")
        # Turns the data into a string, it is still however ciphertext
        try: # Try because the decryption may fail (e.g. with partial ciphertext)
            decrypted = cipher.decrypt(receaved)
            # Decrypt the data
        except Exception as e:
            print("[!] Failed to decrypt message from {}:{}".format(self.ip,self.port))
            print("[!]         - {}".format(e))
            return True
            # There are many different decryption faliure types, so a generic exception is needed
        return (decrypted)

    def recvBytes(self, cipher):
        try:
            receaved = self.socket.recv(2048)
            decrypted = cipher.decrypt(receaved)
            # Recieve and decrypt the data from the client
            return decrypted
        except ConnectionResetError:
            # Excepts an error if the client has disconnected
            print("[=] Connection has been lost with {}:{}".format(self.ip,self.port))
            self.socket.close()
            # Closing the disconnected socket
            self.RemoveInstance(self)
            # Completely removes the client form the server as a connected user
            self.connectionlost = True
            return True
        except ValueError:
            print("[=] Connection has been lost with {}:{}".format(self.ip,self.port))
            self.socket.close()
            self.RemoveInstance(self)
            self.connectionlost = True
            return True

    def sendDiffieHellman(self):
        self.sendKey = pow(int(self.Base),int(self.Secret),int(self.Prime))
        # Base ^ Secret Mod Prime
        self.socket.send(bytes(str(  (str(self.Base)+" "+str(self.Prime)+" "+str(self.sendKey))  ), 'utf-8'))
        # Send Base, Prime and SendKey to client. Structure using something like "Base Prime Key"
        self.recvkey = self.socket.recv(1024)
        # The client will do a similar equation, and then send their response to the server
        self.recvkey = self.recvkey.decode("utf-8")
        # Turns the data into plaintext rather than bytes
        self.DiffieHellman = pow(int(self.recvkey),int(self.Secret),int(self.Prime))
        # Computes the final key to use for the cipher
        # recvkey ^ Secret Mod Prime
        # (g^a mod p)^b mod p = g^ab mod p      (This is the number the server has)
        # (g^b mod p)^a mod p = g^ba mod p      (This is the number the client has)
        # They are the same number
        return self.DiffieHellman

    def login(self):
        self.instance = self.recvBytes(self.initialAES)
        # Recieves the pickled instance the user sent to the server (Storing the credentials)
        if self.loginAttempts > 3: # User cannot exceed 3 login attempts per connection
            print("[!] Max login attempts from {}:{}".format(self.ip,self.port))
            self.send("LAE",self.initialAES) # Login Attempts Exceeded
            self.socket.close()
            self.RemoveInstance(self)
            # Removes the instance from the server; Disconnect the user
            self.connectionlost = True
            return False
        if self.instance == True or self.instance == False or self.instance == None or self.instance == 0:
            # A basic check to make sure the instance is valid
            self.connectionlost = True
            print("[=] Connection has been lost with 'Not logged in' [{}:{}]".format(self.ip, self.port))
            self.socket.close()
            self.RemoveInstance(self)
            # If the instance is not valid, remove the connection
            return
        self.instance = bytes.fromhex(self.instance)
        self.credentials = pickle.loads(self.instance)
        # Turns the pickled instance into a usable instance
        if self.credentials.createaccount == True:
            if self.database.allowedCreateAccount(self.ip, self.port, self.credentials.username):
                self.database.AppendClientsDatabase(self.ip, self.port, self.credentials.username, self.credentials.password, "Standard")
                # If the user wants to create an account and is eligable to then create an account
                print("[+] User added to database:",self.ip, self.port, self.credentials.username, "Standard")
                self.send("ASC", self.initialAES) # Account successfully Created
                # Tell the user the account was created
                self.loggedIn = True
                return True
            else:
                print("[=] Sending Error")
                self.send("ERR-You have already made an account!", self.initialAES)
                # If the user is not allowed to create the account, notify them
        elif self.database.checkPassword(self.credentials.username, self.credentials.password):
                # If the user has the same password as the one in the database then they are logged in
                self.loggedIn = True
                self.database.updateUser(self.credentials.username,ip=self.ip, port=self.port)
                self.database.PrintCustomerContents()
                # Update the ip and port in the database (Shows last connection)
                self.send("SLI", self.initialAES) # Successfully Logged In
                # Notify the user of the successful login
                return True
        else:
            self.loggedIn = False
            self.send("ERR-You have entered an incorrect username or password!", self.initialAES)
            # Tell the user the username or password is incorrect if they are not valid
            self.loginAttempts+=1
            # Incriments the login attempt counter, if it is greater than 3 the user is disconnected
            return False

    def RemoveInstance(self, instance):
        counter=0
        for i in InstanceList:
            # Loops through the connected users
            if instance == i:
                instance.socket.close()
                InstanceList.pop(counter)
                # If the user passed in as the perameter is connected, disconnect
                # Them and then remove them from the connected users array
                return
            counter+=1

    @Logger
    # The user, account type and message is all logged using this wrapper function
    def DistributeMessage(self, message, sentfrom, accountType):
        print("[+] ["+sentfrom+"-"+accountType+"] "+message)
        # A message to the console to show messages sent from users
        itteration = len(InstanceList)
        delInstanceList = []
        for connecitons in reversed(InstanceList):
            # Reversed the array because later on elements are going to be "popped" from the array, this would displace other elements
            print(connecitons.loggedIn, not connecitons.sendingFiles, self.credentials.username not in connecitons.BlockedUsers)
            if connecitons.loggedIn and not connecitons.sendingFiles and self.credentials.username not in connecitons.BlockedUsers and not (self.credentials.username == connecitons.credentials.username):
                # If the user is able to accept messages
                try:
                    connecitons.send("MSG|"+str(sentfrom)+"|"+str(accountType)+"|"+str(message), connecitons.initialAES)
                    print("Sent the message to the client")
                    # Try and send the message to the user, along with account name and account type
                except:
                    print("[!] Couldn't send a message to "+connecitons.credentials.username +" [{}:{}]".format(connecitons.ip, connecitons.port))
                    print("[=]      - Removing {} from connected clients".format(connecitons.credentials.username))
                    self.RemoveInstance(connecitons) # Removes the instance from the list, therefore removing the connection
                    # Catches errors from sending the message, logs to console and then disconnects the conflicting user
            itteration-=1

    def download(self, *args):
        self.sendingFiles = True
        size = int(args[0][1])
        filename = args[0][0]
        # Grab the file name and size from the arguments (They are passed in as an array within args; [ [,] , ] )
        print("[+] File upload request from {}, filename: '{}' with size {} - [{}:{}]".format(self.credentials.username, filename, size, self.ip, self.port))
        # Log that a user is attempting a file upload
        if os.path.isfile("UserFiles\\"+filename):
            print("[!] File '{}' already exists  - {} [{}:{}]".format("UserFiles\\"+filename,self.credentials.username, self.ip, self.port))
            # Checks if a file of that name already exists on the server
            self.send("FAE",self.initialAES) # File Already Exists
            self.sendingFiles=False
            return
            # Notifies the user that the file exists, then quits function
        else:
            print("Downloading file '{}' from {} [{}:{}]".format(filename, self.credentials.username, self.ip, self.port))
            self.send("STS",self.initialAES) # Safe to Send
            # Allow the user to send the file to the server

        with open("UserFiles\\"+filename,"wb") as f:
            encFile=self.socket.recv(size)
            # Download the file
            encFile = self.initialAES.decrypt(encFile)
            # Decrypt it
            encFile = binascii.unhexlify(encFile)
            # Turn it to usable bytes
            f.write(encFile)
            # Write to a file
        print("[+] Done downloading '{}' from {} [{}:{}]".format(filename,self.credentials.username,self.ip, self.port))
        self.sendingFiles = False

    def upload(self, *args):
        self.sendingFiles = True
        filename=args[0][0]
        pathfile = "UserFiles/"+str(filename)
        # Gets the filename that the user has requested
        if os.path.isfile(pathfile):
            # Checks to see if it is a valid file
            print("[^] Sending '{}' to {} [{}:{}]".format(pathfile,self.credentials.username,self.ip, self.port))
            self.send("FileDownload|"+str(filename)+"|"+str(os.path.getsize(pathfile)),self.initialAES)
            # Prepare the user to download a file
            with open(pathfile,"rb") as f:
                toencrypt = binascii.hexlify(f.read(os.path.getsize(pathfile))).decode("utf-8")
                # Read the whole file and turn it into hex
            encrypted = self.initialAES.encrypt(toencrypt)
            # Encrypt the file
            time.sleep(1)
            self.send(str(len(encrypted)),self.initialAES)
            # Send the length of the encrypted file to the user
            # This is so the user knows how much to download
            print("Sent length:",os.path.getsize(pathfile))
            self.socket.send(encrypted)
            # Send the actual file
            print("[=] Done uploading '{}' to {} [{}:{}]".format(pathfile, self.credentials.username, self.ip, self.port))
            # Log that the file has been uploaded to the user
        else:
            self.send("FNF", self.initialAES)
            # The file was not found on the server, so notifying the user
            print("[!] File '{}' not found [{} {}:{}]".format(pathfile, self.credentials.username, self.ip, self.port))
        self.sendingFiles = False

    def BlockUser(self, *args):
        usernames = args[0][0].split(" ")
        # A list of the names a user wants to block
        for x in usernames: # Loop through the users to block
            if not self.database.EditBlockedDatabase(self.credentials.username,x,"Blocked"):
                # If the user tries blocking someone who is not a valid user
                print("[!] Client {} tried blocking {} but they are not in database".format(self.credentials.username,x))
                if self.credentials.username == x:
                    print("[-] {} tried blocking themself".format(self.credentials.username))
                    self.send("MSG|Server|Admin|You cannot block youself.",self.initialAES)
                    # Logs that a user tried blocking themself and then tells the user
                else:
                    print("[!] {} tried blocking {} but they are not in the database".format(self.credentials.username, x))
                    self.send("MSG|Server|Admin|There is no such user {}".format(x),self.initialAES)
                    # Notifies the user that they tried blocking someone that doesnt exist
            else:
                print("[+] {} blocked {}".format(self.credentials.username, x))
                self.send("MSG|Server|Admin|User {} has been blocked".format(x),self.initialAES)
                # Notify the user that they have successfully blocked the user
        self.BlockedUsers = self.database.currentlyBlockedUsers(self.credentials.username)
        # Update the currently blocked users for this instance's user

    def UnblockUser(self, *args):
        usernames = args[0][0].split(" ")
        # Unblock many users
        for x in usernames:
            # Loop through each user to unblock
            if not self.database.EditBlockedDatabase(self.credentials.username,x,"Unblocked"):
                # Unblock the user if the user exists
                # If EditBlockedDatabase returns True then the user has been unblocked
                if self.credentials.username == x:
                    self.send("MSG|Server|Admin|There is no reason to unblock youself",self.initialAES)
                    # Notifies the user that they cannot unblock themself
                else:
                    self.send("MSG|Server|Admin|There is no user {}".format(x),self.initialAES)
                    # Notifies the user that they cannot unblock a non-existent user
            else:
                self.send("MSG|Server|Admin|User {} has been unblocked".format(x), self.initialAES)
                # Notifies the user that they unblocked the user
        self.BlockedUsers = self.database.currentlyBlockedUsers(self.credentials.username)
        # Updates the user's blocked users

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
            # A large list of commands avaliable to the client

        if self.__class__ == Admins: # This allows admins to manipulate their extended privs inherited from Admins class
            # Key - [FunctionReference, Description, Example]
            self.switcher["/Createadmin"] = [self.CreateAdminAccount,"Creates an admin account","/CreateAdmin [Username] [Password]"]
            self.switcher["/Ban"] = [self.BanUser,"Bans a user from the server","/Ban [Username]"]
            self.switcher["/Removeaccount"] = [self.RemoveAccount,"Deletes a users account","/RemoveAccount [Username]"]
            self.switcher["/Editaccount"] = [self.EditMember,"Edit an account","/EditAccount [Username] [AccountType]/[Password]=[Value]"]
            self.switcher["/Search"] = [self.SearchMessages,"Search for messages","/Search [Username or * for all] [Search string]"]
            # This is only for the admins class

        while not self.connectionlost and MainThreadClose == False: # While the client is connected run
            try:
                data = self.recv(self.initialAES)
                # Recieve the data from the user
                self.database.AddMessage(self.credentials.username,data)
                # Adds the message the user sent to the database to log it
                if data[:3] == "MSG":
                    self.DistributeMessage(data[4:], self.credentials.username, "Standard" if not self.database.isAdmin(self.credentials.username) else "Admin")
                    # If the message was intended for other users, distribute it to other users
                else:
                    edited = data.split("|")
                    # If it is a command, then split up the data into an array
                    try:
                        self.switcher[edited[0].title()][0](edited[1:])
                        # This part is incredibly important for the server, any message/command that is sent to the server will end up here
                        # Once the user has logged in. The command will be checked to see if it is in the avaliable commands dictionary (Turned
                        # into a title so that it doesn't have to be capitalised) If it is in the dictionary then the function correlating will
                        # be run and the data is passed into the fucntion
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
        self.send("Logout",self.initialAES)
        # Sends the disconnect message to the client so the client knows to change screen

    def handler(self): # This is run in a thread, one for each client
        self.sendDiffieHellman() # sets AES Key variable
        self.initialAES = AESCipher(hex(int(self.DiffieHellman))) # Creates the AES Cipher object using the key
        self.send("Encryption cipher working", self.initialAES) # Sends a test message to the client so the client can do a checkPassword
        self.loggedIn=False
        self.contunue = self.login()
        # Runs the login function, if it returns true then the user has successfully logged in
        while not self.contunue and self.connectionlost == False:
            # While the user is not logged in and the connection has not been lost
            self.contunue = self.login() # Makes sure the user is logged in to an account
        if self.connectionlost:
            return
        if self.database.isAdmin(self.credentials.username):
            self.__class__ = Admins
            # Elevates the privelages to admin if they login to an admin account
            print("[+] {} logged in as an Admin from {}:{}".format(self.credentials.username, self.ip, self.port))
        else:
            print("[+] {} logged in as a Member from {}:{}".format(self.credentials.username, self.ip, self.port))
            # Displays who has logged in and from what ip / account type
        self.MessengerInterface()
        # Starts listening for messages and responding to commands

class Admins(Members):
    def __init__(self, ip, port, nickname, password):
        super().__init__(ip, port, nickname, password)

    def BanUser(self, data): # Possibly ban users from an ip address / Range
        try:
            self.database.updateUser(data[0], password="Banned")
        except:
            self.send("MSG|Server|Admin|Failed to ban account {}".format(data[0]),self.initialAES)

    def RemoveAccount(self, username): # A function to remove user accounts
        try:
            self.database.CommandDB("DELETE FROM clients WHERE username = ?", username[0])
        except:
            self.send("MSG|Server|Admin|Failed to remove account {}".format(username[0]),self.initialAES)

    def EditMember(self, username, **kwargs): # self.EditMember("Nick",ip="127.0.0.1") - This format using kwargs
        pass

    def SearchMessages(self, data):
        split = data[0].split(" ")
        searchTerm = " ".join(split[1:])
        username = split[0]
        if username == "*":
            databaseData = self.database.CommandDB("SELECT message FROM messages")
        else:
            databaseData = self.database.CommandDB("SELECT message FROM messages WHERE username = ?",username)
        print(databaseData)
        returnString=""
        for x in databaseData:
            returnString+=x[0]+"\n"
        print(returnString)
        # self.send("MSG|Server|Admin|")


    def CreateAdminAccount(self,*args): # Creates admin accounts
        split = args[0][0].split(" ")
        if len(split) < 2:
            self.send("MSG|Server|Admin|Another argument is needed in the format '/Createadmin [Username] [Password]'",self.initialAES)
            # The user has to enter a username as well as a password, so an error message is displayed if the arguments are less than 2
        else:
            if self.database.allowedCreateAccount:
                self.database.AppendClientsDatabase("N/A",0,split[0],self.initialAES.hasher(split[1]),"Admin")
                # Creates an admin account if there is no pre-existing account with that name
                print("[+] Admin account {} has been created by {}".format(split[0],self.credentials.username))
                self.send("MSG|Server|Admin|Admin Account {} has been successfully created".format(split[0]),self.initialAES)
                # Notifies the user of the account creation
            else:
                print("[!] Admin account {} couldn't be made by {}".format(split[0],self.credentials.username))
                self.send("MSG|Server|Admin|Admin account {} could not be created, try a different username".format(split[0]),self.initialAES)
                # The account couldn't be created because an existing account with that name is present

distributeThreads = []
# Used to store threads, many connections may be needed with one thread per connection
MainThreadClose = False
print("[*] Searching for connections")
while 1: # Stuff here for accepting connections # Leading to create a seperate thread for connected clients
    try: # Nesting "try" so that the output looks cleaner when KeyboardInterrupt occurs (Stops multiple errors displaying)
        try:
            connection, ip = sock.accept()
            # Accept incoming connection
            InstanceList.append(Members(connection,ip[0], ip[1]))
            # Create the instance for the client, and then add it to the connected clients list
            print("[+] "+str(ip[0])+":"+str(ip[1])+" Connected!")
            distributeThreads.append(threading.Thread(target=InstanceList[len(InstanceList)-1].handler))
            # Create the thread to handle the connection
            distributeThreads[len(distributeThreads)-1].deamon = True
            distributeThreads[len(distributeThreads)-1].start()
            # Start the thread
        except socket.timeout: # Occurs every second, therefore no code to be run
            pass
    except KeyboardInterrupt:
        # Catch the CTRL-C to stop the program
        banner()
        print("[!] KeyboardInterrupt occured, quitting when all connecitons have dropped")
        MainThreadClose = True
        quit(0)
