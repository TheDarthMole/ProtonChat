# Importing modules
import socket, sys, os, time, sqlite3, select, threading, pickle, binascii, base64, hashlib, traceback
from random import randint
try:
    from Crypto import Random
    from Crypto.Cipher import AES
except ImportError:
    OUTPUT "[!] pyCrypto module not installed! Install using in cmd 'py -m pip install pyCrypto' "
    exit(1)
try:
    from requests import get # Non-standard library
except ImportError:
    OUTPUT "[!] requests module not installed, however it is not necessary"
# Declare public variables AND initialize
HOST <- "0.0.0.0"
ClientMax <- 10
PORT <- 65528
"""
[+] = Added
[*] = Changed
[^] = Moved
[=] = No Changes
[x] = Deleted
[!] = Bugs
"""
# External function declerations
FUNCTION banner():
    OUTPUT "  _____           _"
    OUTPUT " =  __ \         = ="
    OUTPUT " = |__) | __ ___ | |_ ___  _ __"
    OUTPUT " =  ___/ '__/ _ \| __/ _ \| '_ \ "
    OUTPUT " = =   = = = (_) = || (_) | | | |"
    OUTPUT " |_|   |_|  \___/ \__\___/|_| |_|"
    OUTPUT " Server v 1.0 = Nicholas Ruffles"
    OUTPUT "      OCR Computer Science\n"
ENDFUNCTION

FUNCTION getLocalIP():
    s <- socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80)) # 8.8.8.8 is Googles DNS server; its an ip not going to change anytime soon
    localip=s.getsockname()[0]
    s.close()
    RETURN localip
ENDFUNCTION

    import logging
    from functools import wraps
    logging.basicConfig(filename <- "{}.log".format(orig_func.__name__), level <- logging.INFO)
                                            ENDFOR
    @wraps(orig_func)
    FUNCTION wrapper(*args, **kwargs):
                                                         ENDFOR
        RETURN orig_func(*args, *kwargs)
    ENDFUNCTION

    RETURN wrapper
# Initialization of sockets
ENDFUNCTION

banner()
OUTPUT "[*] Loading Sockets"
sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
OUTPUT "[*] Binding address"
sock.bind((HOST, PORT))
try:
    OUTPUT str("[=] Internal IP: {}".format(getLocalIP()))
                                    ENDFOR
    OUTPUT str("[=] External IP: {}".format(get('https://ipapi.co/ip/').text)) # Non-standard library therefore try, except
                                    ENDFOR
except:
    pass
OUTPUT str("[=] Port: {}".format(PORT))
                         ENDFOR
sock.settimeout(1.0)
sock.listen(ClientMax)
OUTPUT "[*] Listening for a max of "+str(ClientMax)+" clients"
                     ENDFOR
InstanceList <- []
# Class declerations
CLASS SQLDatabase:
    FUNCTION __init__(self, DBFileName):
         dbfile <- DBFileName
    ENDFUNCTION

    FUNCTION CommandDB(self, code, *args): # Semi-universal SQL command executor, however allows SQL injection when variable entered
        with sqlite3.connect( dbfile) as conn:
            db=conn.cursor()
            IF not args:
                db.execute(code) # Tries to stop SQL injection by giving the option for args to be passed in
                                                                                    ENDFOR
            ELSE:
                db.execute(code, args)
            ENDIF
            data <- db.fetchall()
            RETURN data
    ENDFUNCTION

    FUNCTION isAdmin(self, username):
        data <-  CommandDB("SELECT accountType FROM clients WHERE nickname = ?",username)
        IF str(data[0][0]) = "Admin":
            RETURN True
        ENDIF
        RETURN False
    ENDFUNCTION

    FUNCTION PrintCustomerContents(self): # Complete
        data <-  CommandDB("SELECT * FROM clients")
        OUTPUT "\n{:^18} = {:^10} = {:^18} = {:^10} = {:^10}\n".format("IP","PORT","NickName","AccType","Password")+"-"*132
                                                               ENDFOR
        for row in data:
            OUTPUT "{:^18} = {:^10} = {:^18} = {:^10} = {:^10}".format(row[0],row[1],row[2],row[4], row[3])
        ENDFOR
                                                               ENDFOR
        OUTPUT
    ENDFUNCTION

    FUNCTION checkPassword(self, username, password):
        data <-  CommandDB("SELECT password FROM clients WHERE nickname = ?", username)
        IF len(data) = 1 AND data[0][0] = password:
            RETURN True
        ENDIF
        RETURN False
    ENDFUNCTION

    FUNCTION AppendClientsDatabase(self, ip, port, nickname, password, accountType): # Complete
         CommandDB("INSERT INTO clients VALUES (?,?,?,?,?)",ip, port, nickname, password, accountType)
    ENDFUNCTION

    FUNCTION updateUser(self,User,**kwargs):
        for x in ("password","ip","port","accountType","nickname"):
            IF x in kwargs:
                IF x = "password":
                    kwargs["password"] <-  initialAES.hasher(kwargs["password"]) # Turns the plaintext password into a database usable password
                ENDIF
                 CommandDB("UPDATE clients SET {} = ? WHERE nickname = ?".format(x),kwargs[x],User)
            ENDIF
    ENDFUNCTION

        ENDFOR
                                                                              ENDFOR
    FUNCTION allowedCreateAccount(self, ip, port, username): # Checks to see IF the users ip AND port are already in the database
                                                                        ENDIF
        IF  CommandDB("SELECT * FROM clients WHERE ip = ? AND port = ?",ip, port):
            RETURN False
        ENDIF
        IF  CommandDB("SELECT * FROM clients WHERE nickname = ?",username):
            RETURN False
        ENDIF
        RETURN True
    ENDFUNCTION

    FUNCTION CreateClientsTable(self):
        try:
             CommandDB("CREATE TABLE clients (ip text, port integer, nickname text, password text, accountType text, PRIMARY KEY (nickname))")
            OUTPUT "[+] Clients Database successfully created"
        except sqlite3.OperationalError:
            OUTPUT "[=] Clients Database already created"
    ENDFUNCTION

    FUNCTION CreateBlockedTable(self):
        try:
             CommandDB("CREATE TABLE blockedUsers (relatingUser text NOT NULL,\
                            relationalUser text NOT NULL,\
                            type text NOT NULL,\
                            PRIMARY KEY (relatingUser, relationalUser),\
                            FOREIGN KEY (relatingUser) REFERENCES clients(nickname),\
                            FOREIGN KEY (relationalUser) REFERENCES clients(nickname))")
            OUTPUT "[+] Blocked Users Database successfully created"
        except  sqlite3.OperationalError:
            OUTPUT "[=] Blocked Users Database already created"
    ENDFUNCTION

    FUNCTION PrintBlockedContents(self): # Prints all of blockedUsers table with headders
        data <-  CommandDB("SELECT * FROM blockedUsers")
        OUTPUT "\n{:^16} = {:^16} = {:^7}\n".format("RelatingUser","RelationalUser","Type")+"-"*59
                                            ENDFOR
        for row in data:
            OUTPUT "{:^16} = {:^16} = {:^7}".format(row[0],row[1],row[2])
        ENDFOR
                                            ENDFOR
        OUTPUT
    ENDFUNCTION

    FUNCTION EditBlockedDatabase(self, Relating, Relational, Type):
        IF Relating = Relational:
            OUTPUT "[!] {} tried blocking themself".format(Relating)
                                                   ENDFOR
            RETURN False
        ENDIF
        for x in (Relating, Relational):
            IF not  CommandDB("SELECT nickname FROM clients WHERE nickname = ?",x):
                OUTPUT "[=] {} tried blocking {} who is not in the database".format(Relating,x)
                                                                            ENDFOR
                RETURN False # Returns false becasue the client is not in the table
            ENDIF
        ENDFOR
         CommandDB("INSERT OR REPLACE INTO blockedUsers (relatingUser, relationalUser,type) VALUES (?,?,?)",Relating, Relational,Type)
         PrintCustomerContents()
        RETURN True
    ENDFUNCTION

    FUNCTION isBlocked(self, Relating, Relational,Type="Blocked"):
        data <-  CommandDB("SELECT * FROM blockedUsers WHERE relatingUser = ? AND relationalUser = ? AND type <- ?", Relating, Relational, Type)
        RETURN True IF data else False
                    ENDIF
    ENDFUNCTION

    FUNCTION currentlyBlockedUsers(self, Relating, Type="Blocked"):
        data <-  CommandDB("SELECT relationalUser FROM blockedUsers WHERE relatingUser = ? AND type = ?",Relating, Type)
        sterilizedOutput <- []
        for x in data:
            sterilizedOutput.append(x[0])
        ENDFOR
        RETURN sterilizedOutput
    ENDFUNCTION

    FUNCTION CreateMessageTable(self):
        try:
             CommandDB("CREATE TABLE messages (username text NOT NULL,\
                            message text NOT NULL,\
                            timedate text NOT NULL,\
                            FOREIGN KEY (username) REFERENCES clients(nickname))")
            OUTPUT "[+] Messages Database successfully created"
        except sqlite3.OperationalError:
            OUTPUT "[=] Messages Database already created"
    ENDFUNCTION

    FUNCTION AddMessage(self, user, message):
        IF  CommandDB("SELECT nickname FROM clients WHERE nickname = ?",user):
             CommandDB("INSERT INTO messages (username, message, timedate) VALUES (?,?,?)",user,message,time.asctime(time.localtime(time.time())))
        ELSE:
            OUTPUT "[!] User {}'s record cant be added to messages database, user not in clients database"
        ENDIF
    ENDFUNCTION

    FUNCTION PrintMessagesContents(self):
        data <-  CommandDB("SELECT * FROM messages")
        OUTPUT "\n{:^26} = {:^16} = {:^10}\n".format("Date AND Time","Username","Message")+"-"*59
                                             ENDFOR
        for row in data:
            OUTPUT "{:^26} = {:^16} = {:^10}".format(row[2],row[0],row[1])
        ENDFOR
                                             ENDFOR
        OUTPUT
    ENDFUNCTION

    FUNCTION dump(self, *args): # Made for Debugging, however mey be useful elsewhere
                                  ENDFOR
        for x in args:
             CommandDB("DELETE FROM {}".format(x))
    ENDFUNCTION

ENDCLASS

        ENDFOR
                                            ENDFOR
DataBase <- SQLDatabase("LoginCredentials.db")
os.remove("LoginCredentials.db")
DataBase.CreateClientsTable()
DataBase.CreateBlockedTable()
DataBase.CreateMessageTable()
DataBase.dump("clients","blockedUsers","messages") # Purely for testing (Stops duplicates)
                                                            ENDFOR
DataBase.AppendClientsDatabase("1.3.3.7",666,"Nick1","bcc014de6fb06f937156515b8f36fb2a995c037f441862411160f4b48f1ad602","Standard")
DataBase.AppendClientsDatabase("1.3.3.7",666,"Nick","bcc014de6fb06f937156515b8f36fb2a995c037f441862411160f4b48f1ad602","Admin")
DataBase.PrintCustomerContents()
DataBase.PrintBlockedContents()
DataBase.PrintMessagesContents()
CLASS UserCredentials:
    FUNCTION __init__(self, username, password, createaccount):
         username <- username
         password <- password
         createaccount <- createaccount
    ENDFUNCTION

ENDCLASS

CLASS AESCipher(object):
    FUNCTION __init__(self, key):
         key <-  hasher(key)
    ENDFUNCTION

    FUNCTION hasher(self, password):
        salt <- b'\xdfU\xc1\xdf\xf9\xb30\x96' # This is the default salt i am using for client AND server side
                                                           ENDFUNCTION

                                                                                   ENDFOR
        RETURN (  hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"), salt, 1000000)  )
    ENDFUNCTION

    FUNCTION encrypt(self, raw):
        b64 <- base64.b64encode(raw.encode("utf-8")).decode("utf-8") # Turned to base64 because it stops a weird padding error in the module
        raw <-  pad(b64)                                         # That stops the £ symbol being sent
        rawbytes <- bytes(raw,"utf-8")
        iv <- Random.new().read(AES.block_size)
        cipher <- AES.new( key, AES.MODE_CBC, iv)
        RETURN base64.b64encode(iv + cipher.encrypt(rawbytes))
    ENDFUNCTION

    FUNCTION decrypt(self, enc):
        enc <- base64.b64decode(enc)
        iv <- enc[:AES.block_size]
        cipher <- AES.new( key, AES.MODE_CBC, iv)
        RETURN base64.b64decode( unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')).decode("utf-8")
    ENDFUNCTION

    FUNCTION pad(self,s): # Pads the string so that it complys with the AES 16 byte block size
        RETURN s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)
    ENDFUNCTION

    FUNCTION unpad(self, s): # Turns the 16 byte complyant string to a normal string
        RETURN s[:-ord(s[len(s)-1:])]
    ENDFUNCTION

ENDCLASS

CLASS Members:
    FUNCTION __init__(self, connection, ip, port):
         ip <- ip
         port <- port
         socket <- connection
         nickname <- None
         code <- None
         DiffieHellman <- None
              ENDIF
         Prime <- """529204664323527979712946862439191145311982207310489934007\
    ENDFUNCTION

ENDCLASS

464831218031464077205916042049447783375725379654966060134\
402111426034716246754987996475613641992085506553374675640\
6145751654070887955334806643930700832559492186669690829"""
         Prime <- int( Prime)
         Base <- randint(2,3)
         Secret <- randint(2**100, 2**150)
         initialAES <- None
         finalAES <- None
         database <- SQLDatabase("LoginCredentials.db")
         connectionlost <- False
         loggedIn <- False
         sendingFiles <- False
         loginAttempts <- 0
         BlockedUsers <- []
    @Logger
    FUNCTION send(self, toSendToClient, cipher):
        toSendToClient <- cipher.encrypt(toSendToClient)
         socket.send(toSendToClient)
    ENDFUNCTION

    FUNCTION recv(self, cipher):
        try:
            receaved <-  socket.recv(2048)
        except ConnectionResetError:
            try:
                OUTPUT "[=] {} {} disconnected from the server - [{}:{}]".format("Admin" IF  database.isAdmin( credentials.username) else "Standard",  credentials.username, ip,  port)
                                                                                        ENDIF
                                                                         ENDFOR
            except:
                OUTPUT "[=] Connection has been lost with {}:{}".format( ip, port)
                                                                ENDFOR
             RemoveInstance(self)
             connectionlost <- True
            RETURN True
        receaved <- receaved.decode("utf-8")
        try:
            decrypted <- cipher.decrypt(receaved)
        except Exception as e:
            OUTPUT "[!] Failed to decrypt message from {}:{}".format( ip, port)
                                                             ENDFOR
            OUTPUT "[!]         - {}".format(e)
                                     ENDFOR
            RETURN True
        RETURN (decrypted)
    ENDFUNCTION

    FUNCTION recvBytes(self, cipher):
        try:
            receaved <-  socket.recv(2048)
            decrypted <- cipher.decrypt(receaved)
            RETURN decrypted
        except ConnectionResetError:
            OUTPUT "[=] Connection has been lost with {}:{}".format( ip, port)
                                                            ENDFOR
             socket.close()
            counter <- 0
             RemoveInstance(self)
             connectionlost <- True
            RETURN True
    ENDFUNCTION

    FUNCTION sendDiffieHellman(self):
         sendKey <- pow(INTERGER(Base),INTERGER(Secret),INTERGER(Prime))
         CALL socket.send(bytes(str((STRING(Base)+" "+STRING(Prime)+" "+STRING(sendKey))), 'utf-8'))
         recvkey <-  socket.recv(1024)
         recvkey <-  recvkey.decode("utf-8")
         DiffieHellman <- pow(INTERGER( recvkey),INTERGER(Secret),INTERGER(Prime))
         RETURN  DiffieHellman
    ENDFUNCTION

    FUNCTION login(self):
         instance <-  recvBytes( initialAES)
        IF  loginAttempts > 3:
            OUTPUT "[!] Max login attempts from {}:{}".format( ip, port)
                                                      ENDFOR
             send("LAE", initialAES) # Login Attempts Exceeded
             RemoveInstance(self)
             connectionlost <- True
            RETURN False
        ENDIF
        IF  instance = True OR  instance = False OR  instance = None OR  instance = 0:
             connectionlost <- True
            OUTPUT "[=] Connection has been lost with 'Not logged in' [{}:{}]".format( ip,  port)
                                                                              ENDFOR
             RemoveInstance(self)
            RETURN
        ENDIF
         instance <- bytes.fromhex( instance)
         credentials <- pickle.loads( instance)
        IF  credentials.createaccount = True:
            IF  database.allowedCreateAccount( ip,  port,  credentials.username):
                 database.AppendClientsDatabase( ip,  port,  credentials.username,  credentials.password, "Standard")
                OUTPUT "[+] User added to database:", ip,  port,  credentials.username, "Standard"
                 send("ASC",  initialAES) # Account successfully Created
                 loggedIn <- True
                RETURN True
            ELSE:
                OUTPUT "[=] Sending Error"
                 send("ERR-You have already made an account!",  initialAES)
            ENDIF
        ELSEIF  database.checkPassword( credentials.username,  credentials.password):
                 loggedIn <- True
                 database.updateUser( credentials.username,ip= ip, port= port)
                 send("SLI",  initialAES)
                RETURN True
        ELSE:
             loggedIn <- False
             send("ERR-You have entered an incorrect username or password!",  initialAES)
             loginAttempts+=1
            RETURN False
        ENDIF
    ENDFUNCTION

    FUNCTION RemoveInstance(self, instance):
        counter=0
        for i in InstanceList:
            IF instance = i:
                instance.socket.close()
                InstanceList.pop(counter)
                RETURN
            ENDIF
            counter+=1
    ENDFUNCTION

        ENDFOR
    @Logger
    FUNCTION DistributeMessage(self, message, sentfrom, accountType):
        OUTPUT "[+] ["+sentfrom+"-"+accountType+"] "+message
        itteration <- len(InstanceList)
        delInstanceList <- []
        for connecitons in reversed(InstanceList):
            IF connecitons.loggedIn AND not connecitons.sendingFiles AND  credentials.username not in connecitons.BlockedUsers:
                try:
                    connecitons.send("MSG|"+str(sentfrom)+"|"+str(accountType)+"|"+str(message), connecitons.initialAES)
                except:
                    OUTPUT "[!] Couldn't send a message to "+connecitons.credentials.username +" [{}:{}]".format(connecitons.ip, connecitons.port)
                                                                                                         ENDFOR
                    OUTPUT "[=]      - Removing {} from connected clients".format(connecitons.credentials.username)
                                                                          ENDFOR
                     RemoveInstance(connecitons) # Removes the instance from the list, therefore removing the connection
            ENDIF
                                                                                                ENDFOR
            itteration-=1
    ENDFUNCTION

        ENDFOR
    FUNCTION download(self, *args):
         sendingFiles <- True
        size <- int(args[0][1])
        filename <- args[0][0]
        OUTPUT "[+] File upload request from {}, filename: '{}' with size {} - [{}:{}]".format( credentials.username, filename, size,  ip,  port)
                                                                                       ENDFOR
        IF os.path.isfile("UserFiles\\"+filename):
            OUTPUT "[!] File '{}' already exists  - {} [{}:{}]".format("UserFiles\\"+filename, credentials.username,  ip,  port)
                                                               ENDFOR
             send("FAE", initialAES) # File Already Exists
             sendingFiles=False
            RETURN
        ELSE:
            OUTPUT "Downloading file '{}' from {} [{}:{}]".format(filename,  credentials.username,  ip,  port)
                                                          ENDFOR
             send("STS", initialAES) # Safe to Send
        ENDIF
        with open("UserFiles\\"+filename,"wb") as f:
            encFile= socket.recv(size)
            encFile <-  initialAES.decrypt(encFile)
            encFile <- binascii.unhexlify(encFile)
                                     ENDIF
            f.write(encFile)
        OUTPUT "[+] Done downloading '{}' from {} [{}:{}]".format(filename, credentials.username, ip,  port)
                                                          ENDFOR
         sendingFiles <- False
    ENDFUNCTION

    FUNCTION upload(self, *args):
         sendingFiles <- True
        filename=args[0][0]
        pathfile <- "UserFiles/"+str(filename)
        IF os.path.isfile(pathfile):
            OUTPUT "[^] Sending '{}' to {} [{}:{}]".format(pathfile, credentials.username, ip,  port)
                                                   ENDFOR
             send("FileDownload|"+str(filename)+"|"+str(os.path.getsize(pathfile)), initialAES)
            with open(pathfile,"rb") as f:
                toencrypt <- binascii.hexlify(f.read(os.path.getsize(pathfile))).decode("utf-8")
                                         ENDIF
            encrypted <-  initialAES.encrypt(toencrypt)
            time.sleep(1)
             send(str(len(encrypted)), initialAES)
            OUTPUT "Sent length:",os.path.getsize(pathfile)
             socket.send(encrypted)
            OUTPUT "[=] Done uploading '{}' to {} [{}:{}]".format(pathfile,  credentials.username,  ip,  port)
                                                          ENDFOR
        ELSE:
             send("FNF",  initialAES)
            OUTPUT "[!] File '{}' not found [{} {}:{}]".format(pathfile,  credentials.username,  ip,  port)
        ENDIF
                                                       ENDFOR
         sendingFiles <- False
    ENDFUNCTION

    FUNCTION BlockUser(self, *args):
        usernames <- args[0][0].split(" ")
         database.PrintBlockedContents()
        for x in usernames:
            IF not  database.EditBlockedDatabase( credentials.username,x,"Blocked"):
                OUTPUT "CLient {} not in database".format(x)
                                                  ENDFOR
                IF  credentials.username = x:
                     send("MSG|Server|Admin|You cannot block you ", initialAES)
                ELSE:
                     send("MSG|Server|Admin|There is no such user {}".format(x), initialAES)
                ENDIF
                                                                          ENDFOR
            ELSE:
                OUTPUT "CLient {} in database".format(x)
                                              ENDFOR
                 send("MSG|Server|Admin|User {} has been blocked".format(x), initialAES)
            ENDIF
        ENDFOR
                                                                      ENDFOR
         BlockedUsers <-  database.currentlyBlockedUsers( credentials.username)
    ENDFUNCTION

    FUNCTION UnblockUser(self, *args):
        usernames <- args[0][0].split(" ")
         database.PrintBlockedContents()
        for x in usernames:
            IF not  database.EditBlockedDatabase( credentials.username,x,"Unblocked"):
                IF  credentials.username = x:
                     send("MSG|Server|Admin|There is no reason to unblock youself", initialAES)
                ELSE:
                     send("MSG|Server|Admin|There is no user {}".format(x), initialAES)
                ENDIF
                                                                     ENDFOR
            ELSE:
                 send("MSG|Server|Admin|User {} has been unblocked".format(x),  initialAES)
            ENDIF
        ENDFOR
                                                                        ENDFOR
         BlockedUsers <-  database.currentlyBlockedUsers( credentials.username)
    ENDFUNCTION

    FUNCTION MessengerInterface(self):
         switcher <- { # Key - [FunctionReference, Description, Example]
            "/Changepassword": [ ChangeStandardPassword,"Changed the password of any user account","/ChangePassword [New Password]"],
            "/Logout": [ Logout,"Logs the user out of their account","/Logout"],
            "/Changeusername": [ ChangeUsername,"Change the username of current account","/Changeusername [NewUsername]"],
            "/Help": [ ShowHelp,"Shows this help menu","/Help"], # A simple help message for the commands
                                                                                             ENDFOR
            "Msg": [ DistributeMessage,"Redistribute a message to other clients","No implimentation"],
            "Uploading": [ download,"Actually downloads the file form the client, once the file is specified","You don't use this command as a client"],
                                                                                                           ENDIF
                                                                     ENDFOR
            "/Upload": [ sendUpload,"Upload a file to the server, use button OR this command + filename","/Upload [FilePath]"], # The users upload is the servers download
            "/Download": [ upload,"Download a file from the server","/Download [FileName]"], # The users download is the servers upload
            "/Block": [ BlockUser,"Blocks a user from sending you messages","/Block [Username] [Optional aditional usernames]"],
            "/Unblock": [ UnblockUser,"Allows a previously blocked user to send you messages","/Unblock [Username] [Optional aditional usernames]"]}
        IF  __class__ = Admins: # This allows admins to manipulate their extended privs inherited from Admins class
                  ENDCLASS

            # Key - [FunctionReference, Description, Example
             switcher["/Createadmin"] <- [ CreateAdminAccount,"Creates an admin account","/CreateAdmin [Username] [Password]"]
             switcher["/Ban"] <- [ BanUser,"Bans a user from the server","/Ban [Username]"]
             switcher["/Removeaccount"] <- [ RemoveAccount,"Deletes a users account","/RemoveAccount [Username]"]
             switcher["/Editaccount"] <- [ EditMember,"Edit an account","/EditAccount [Username] [AccountType]/[Password]=[Value]"]
        ENDIF
        while not  connectionlost AND MainThreadClose = False: # While the client is connected run
            try:
                data <-  recv( initialAES)
                 database.AddMessage( credentials.username,data)
                #  database.PrintMessagesContents()
                IF data[:3] = "MSG":
                     DistributeMessage(data[4:],  credentials.username, "Standard" IF not  database.isAdmin( credentials.username) else "Admin")
                                                                                           ENDIF
                ELSE:
                    edited <- data.split("=")
                    try:
                         switcher[edited[0].title()][0](edited[1:])
                    except KeyError:
                        OUTPUT "[!] Key error occured with data: '{}' from {} [{}:{}]".format(edited[0],  credentials.username,  ip,  port)
                                                                                      ENDFOR
                         send("Keyerror|{}".format(edited[0]), initialAES) # Make an error message here to be displayed on the users screen.
                ENDIF
                                                ENDFOR
            except TypeError:
                 connectionlost <- True
    ENDFUNCTION

        ENDWHILE
    FUNCTION ChangeStandardPassword(self,*args):
        pass
    ENDFUNCTION

    FUNCTION ChangeUsername(self,*args):
        pass
    ENDFUNCTION

    FUNCTION sendUpload(self, *args):
        pass
    ENDFUNCTION

    FUNCTION ShowHelp(self,*args):
        string=""
         send("MSG|Server|Admin|Commands for {}".format( __class__.__name__),  initialAES)
                                                                   ENDCLASS

                                             ENDFOR
        for x in  switcher:
            IF not x in ["Msg","Uploading"]: # Because the "MSG" is not a command, and shows backend structure too easily
                string+="{} {} {}\n".format(x,  switcher[x][1], switcher[x][2])
            ENDIF
        ENDFOR
                                     ENDFOR
         send("MSG|Server|Admin|{}".format(string), initialAES)
    ENDFUNCTION

                                        ENDFOR
    FUNCTION Logout(self,*args):
         send("Logout", initialAES) # Sends the disconnect message to the client so the client knows to change screen
    ENDFUNCTION

    FUNCTION handler(self):
         CALL sendDiffieHellman()
         initialAES <- AESCipher(hex(int( DiffieHellman)))
         CALL send("Encryption cipher working",  initialAES)
         loggedIn <- False
         contunue <-  login()
        WHILE NOT contunue AND connectionlost = False:
             contunue <- login()
        ENDWHILE
        IF database.isAdmin( credentials.username) THEN
             __class__ <- Admins
            OUTPUT "[+] {} logged in as an Admin from {}:{}".format( credentials.username,  ip,  port)
        ELSE:
            OUTPUT "[+] {} logged in as a Member from {}:{}".format( credentials.username,  ip,  port)
        ENDIF
        CALL MessengerInterface()
    ENDFUNCTION

CLASS Admins(Members):
    FUNCTION __init__(self, ip, port, nickname, password):
        super().__init__(ip, port, nickname, password)
    ENDFUNCTION

    FUNCTION BanUser(self): # Possibly ban users from an ip address / Range
        pass
    ENDFUNCTION

    FUNCTION RemoveAccount(self, username):
        pass
    ENDFUNCTION

    FUNCTION CreateAdminAccount(self,*args):
        OUTPUT args
        split <- args[0][0].split(" ")
        IF len(split) < 2:
             send("MSG|Server|Admin|Another argument is needed in the format '/Createadmin [Username] [Password]'", initialAES)
                                                                          ENDFOR
        ELSE:
            OUTPUT split
            IF  database.allowedCreateAccount:
                 database.AppendClientsDatabase("N/A",0,split[0], initialAES.hasher(split[1]),"Admin")
                OUTPUT "[+] Admin account {} has been created by {}".format(split[0], credentials.username)
                                                                    ENDFOR
                 send("MSG|Server|Admin|Admin Account {} has been successfully created".format(split[0]), initialAES)
                                                                                            ENDFOR
            ELSE:
                OUTPUT "[!] Admin account {} couldn't be made by {}".format(split[0], credentials.username)
                                                                    ENDFOR
                 send("MSG|Server|Admin|Admin account {} could not be created, try a different username".format(split[0]), initialAES)
        ENDIF
            ENDIF
                                                                                          ENDIF
    ENDFUNCTION

                                                                                                             ENDFOR
    FUNCTION EditMember(self, username, **kwargs): #  EditMember("Nick",ip="127.0.0.1") - This format using kwargs
                                                                                              ENDFOR
        pass
    ENDFUNCTION

ENDCLASS

distributeThreads <- []
MainThreadClose <- False
OUTPUT "[*] Searching for connections"
                     ENDFOR
while 1: # Stuff here for accepting connections # Leading to create a seperate thread for connected clients
                      ENDFOR
    try: # Nesting "try" so that the output looks cleaner when KeyboardInterrupt occurs (Stops multiple errors displaying)
        try:
            connection, ip <- sock.accept()
            InstanceList.append(Members(connection,ip[0], ip[1]))
            OUTPUT "[+] "+str(ip[0])+":"+str(ip[1])+" Connected!"
            distributeThreads.append(threading.Thread(target=InstanceList[len(InstanceList)-1].handler))
            distributeThreads[len(distributeThreads)-1].deamon <- True
            distributeThreads[len(distributeThreads)-1].start()
        except socket.timeout: # Occurs every second, therefore no code to be run
                                                           ENDFOR
            pass
    except KeyboardInterrupt:
        banner()
        OUTPUT "[!] KeyboardInterrupt occured, quitting when all connecitons have dropped"
        MainThreadClose <- True
        quit(0)
