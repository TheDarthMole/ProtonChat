import socket, threading, sys, ast, os, time, sqlite3
#ast - Library used for turning strings to arrays
from random import randint # Cypher key creation
try:
    from requests import get # Non-standard library, therefore may not be installed
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

DataBaseName = "Clients.db"

def Server():
    # =============================== Start declaring values =============================== #
    PORT = 65530
    #                [User]  [Pass] [IP] [Port]
    UserNames = [] # ["Nick", 1337, None, None]
    encryptionLength = 256 # Cypher key size
    print("[*] Loading Sockets")
    connections = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print ("[*] Binding Address")
    sock.bind(("0.0.0.0", PORT))
    sock.listen(1)
    print("[=] Internal IP:",socket.gethostbyname(socket.gethostname()))
    try: # Doesn't intentionally run non-imported libraries
        print("[=] External IP:",(get('https://ipapi.co/ip/').text)) # [!] Hash out if requests is not installed
    except:
        pass
    print("[=] Port",PORT)
    print("[+] Reading Clients file")
    print("[*] Ready for connections")

    # =============================== Stop declaring values =============================== #
    def is_prime(num, test_count): # Takes
        if num == 1:
            return False
        if test_count >= num:
            test_count = num - 1
        for x in range(test_count):
            val = randint(1, num - 1)
            if pow(val, num-1, num) != 1:
                return False
        return True

    def generateBigPrime(n):
        found_prime = False
        while not found_prime:
            p = randint(2**(n-1), 2**n)
            if is_prime(p, 1000):
                return p

    def DiffyHellmanAssign(encryptionLength): # Diffie-hellman key exchange
        publicBase = randint(100,1000)
        publicPrime = generateBigPrime(encryptionLength)
        privateKey = randint(10000000000000000000000000000000000000000000,100000000000000000000000000000000000000000000)
        sendKey = pow(publicBase, privateKey, publicPrime) # Key to send to client
        print()
        return publicBase, publicPrime, privateKey, sendKey

    # Database File functions start here
    def CommandDB(code): # Semi-universal SQL command executor, however allows SQL injection when variable enterd
        with sqlite3.connect(DataBaseName) as conn:
            db=conn.cursor()
            db.execute(code)
            data = db.fetchall()
            return data

    def PrintCustomerContents(): # Complete
        data = CommandDB("SELECT * FROM clients")
        print("\n       IP           PORT     NickName    Code\n" +"-"*48)
        for row in data:
            print("{:^18}{:^10}{:^10}{:^10}".format(row[0],row[1],row[2],row[3]))

    def CreateClientsTable():
        try:
            CommandDB("CREATE TABLE clients (ip text, port integer, nickname text, password integer, PRIMARY KEY (nickname))")
        except sqlite3.OperationalError:
            print("[=] Database already created")

    def SearchCode(Code): # Complete
        with sqlite3.connect(DataBaseName) as conn:
            db=conn.cursor()
            db.execute("SELECT * FROM clients WHERE code = ?",(Code,))
            data = db.fetchall()
        return data

    def AppendDatabase(ip, port, nickname, code): # Complete
        with sqlite3.connect(DataBaseName) as conn:
            db=conn.cursor()

            db.execute("INSERT INTO clients VALUES (?,?,?,?)",(ip, port, nickname, code))


    def UpdatePortIP(ip, port, code):
        with sqlite3.connect(DataBaseName) as conn:
            db=conn.cursor()
            db.execute("UPDATE clients SET ip = ?, port = ? WHERE code = ?",(ip, port, code))



    # Database File functions finish here
    def handler(c, a):
        publicBase, publicPrime, privateKey, sendKey = DiffyHellmanAssign(encryptionLength)
        try:
            c.send(bytes((str(str(publicBase)+" "+str(publicPrime)+" "+str(sendKey))) ,"utf-8"))
            #print("-------SendKey:",sendKey)
            recvKey = c.recv(4096)
        except ConnectionResetError:
            Terminate = True
        recvKey = recvKey.decode("utf-8") # Client's key modded
        cipherKey = pow(int(recvKey), int(privateKey), int(publicPrime))
        print("[=] cipherKey:",hex(cipherKey),"for",a[0]+":"+str(a[1]))

        # Once keys are exchanged, follow login attemps
        LoginAttempts=0
        while True:
            try:
                data = c.recv(1024)
            except ConnectionResetError:
                print("[x] Connection with",a[0],"was forcibly closed")
                Terminate = True
                break
            print("[+]",(data).decode("utf-8"),"-",a[0])
            data = data.decode("utf-8") # Decoded raw data

            if LoginAttempts >= 4:
                c.send(bytes("FinalRejection",'utf-8'))
                connections.remove(c)
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
                #Here is the append to database
                AppendDatabase(a[0],a[1],data[0],data[1])
                #AppendUsersFile(UserNames) # Appends the updated logins to file
            elif data[:3] == "HL-": # Checking for Hidden Logins
                data = str(data[3:])
                LoginAttempts+=1
                FoundUsername = False
                # Check in databas
                print(SearchCode(data))
                DatabaseData = SearchCode(data)
                if DatabaseData != []:
                    c.send(bytes("Accepted",'utf-8'))
                    print("[*] Code Accepted from",a[0]+":"+str(a[1])+" as "+DatabaseData[0][2])

                    UpdatePortIP(a[0], a[1], data)
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
            NickName = DatabaseData[0][2]
            print(str(NickName)+" Is the nickname")
            print("[+] "+a[0]+" ["+NickName+"]: "+str(data))
            for connection in connections:
                try:
                    #if a[0] == # Check for
                    connection.send((bytes((str("["+ NickName + "] " + data)), 'utf-8'))) # Long string to append and encode message
                except ConnectionResetError :
                    print("[x] Connection with " + str(a[0]) + " Has been terminated")
                    break
                except BrokenPipeError:
                    print("[!] Message from "+str(a[0])+" ["+NickName+"] not sent correctly")
            if not data:
                print("[x] " + str(a[0]) + ":" + str(a[1]),"Disconnected")
                connections.remove(c)
                c.close
                break

    CreateClientsTable()
    PrintCustomerContents()

    while True:
        try: # Only used to catch unexpected connection closures
            c, a = sock.accept()
            connections.append(c)
            print("[*] "+ str(a[0]) + ":" + str(a[1]), "Connected")
            cThread = threading.Thread(target=handler, args=(c, a))
            cThread.deamon = True
            cThread.start()
        except ConnectionResetError:
            print("[!]",a[0],"Closed connection unexpectedly")

# ============================================================================================================================ Finished with server code, now is client code

def Client():
    def sendMessage():
        while True:
            try:
                sock.send(bytes("","utf-8"))
            except:
                return
            try:
                sock.send((bytes(input(""), 'utf-8')))
            except ConnectionResetError:
                break
                pass
            time.sleep(0.3)

    def DiffyHellman(diffieHellman): # Diffie-hellman key exchange
        diffieHellman = diffieHellman.split(" ")
        publicBase, publicPrime, recvKey = diffieHellman
        privateKey = randint(10000000000000000000000000000000000000000000,100000000000000000000000000000000000000000000)
        sendKey = pow(int(publicBase), int(privateKey), int(publicPrime))
        try:
            sock.send(bytes(str(sendKey),"utf-8"))
            cipherKey = pow(int(recvKey), int(privateKey), int(publicPrime))
            print("[=] cipherKey:",hex(cipherKey))
        except ConnectionResetError:
            print("[x] Connection with",address+":"+str(port),"was actively closed")
            BreakConnection = True



    def CodeChecking(BreakConnection):
        # Code entry
        code = 0
        newaccount = input("[+] Would you like to make a new account? (Y/N) ")
        while True:
            if newaccount.upper() == "Y":
                setname = input("[+] Enter your New Username: ")
                while True:
                    setcode = input("[+] Enter your New Code: ")
                    if setcode.isdigit():
                        newaccount = "N"
                        break
                    else:
                        print("[!] Code is not an interger value")
                try:
                    sock.send(bytes(("HR-"+str(setname)+" "+str(setcode)),'utf-8'))
                    print("[+] Account successfully created")
                except ConnectionResetError:
                    print("[x] Connection with",address+":"+str(port),"was actively closed")
            else:
                code = input("[+] Enter you're login code: ")
                try:
                    sock.send(bytes(("HL-"+str(code)),'utf-8')) # Appends "HL-" at beginning
                    codecheck = sock.recv(1024)                # to denote hidden from chat log
                except ConnectionResetError:
                    print("[x] Connection with",address+":"+str(port),"was actively closed")
                    break
                if codecheck.decode('utf-8') == "Accepted":
                    print("[*] Successful Login")
                    print("[=] You can now send messages")
                    break
                elif codecheck.decode('utf-8') == "FinalRejection":
                    print("[x] Final Rejection")
                    exit(0)
                elif codecheck.decode('utf-8') == "Rejection":
                    print("[!] Rejected Code")
        return BreakConnection


    def Connect():
        BreakConnection = False
        try:
            sock.connect((address, port))
            print ("[*] Client Connected to {}:{}".format(address, port))
        except TimeoutError:
            print("[!] The host didn't respond, server could be down etc.")
            return

        try:
            diffieHellman = sock.recv(4096)
            diffieHellman = diffieHellman.decode("utf-8")
            DiffyHellman(diffieHellman)
        except ConnectionResetError:
            BreakConnection = True
            print("[x] Connection with",address+":"+str(port),"was actively closed")

        if not BreakConnection:
            BreakConnection = CodeChecking(BreakConnection) # Calls Code checking function ( Login )
            iThread = threading.Thread(target=sendMessage)
            iThread.deamon = True
            iThread.start()

            while True:
                try:
                    data = sock.recv(1024)
                    if not data:
                        break
                    print(str(data, 'utf-8'))
                except ConnectionResetError:
                    BreakConnection = True
                    print("[x] Connection with",address+":"+str(port),"was actively closed")
                    break

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print ("[*] Socket Setup")

    address = input("Enter the server's IP: ")
    if address == "":
        address = "52.56.116.82" # Set dedicated server here
    port = input("Enter the server's PORT (Default=65530): ")
    if port == "":
        port = 65530 # Dedicated port here
    BreakConnection = False
    # Diffie-hellman key declerations
    publicPrime = None
    publicBase = None
    privateKey = None
    cipherKey = None

    Connect()


def CommandDB(code): # Semi-universal SQL command executor, however allows SQL injection when variable enterd
    with sqlite3.connect(DataBaseName) as conn:
        db=conn.cursor()
        db.execute(code)
        data = db.fetchall()
        return data

def PrintCustomerContents(): # Complete
    data = CommandDB("SELECT * FROM clients")
    print("\n       IP           PORT     NickName    Code\n" +"-"*48)
    for row in data:
        print("{:^18}{:^10}{:^10}{:^10}".format(row[0],row[1],row[2],row[3]))



# ============================================================================================================================== Finished with client code


def Menu():
    print("\n============MENU=========")
    print("||    1.   Server      ||")
    print("||    2.   Client      ||")
    print("||    3. Credentials   ||")
    print("=========================\n")

def Clear():
    if os.name == "posix":
        os.system("clear")
    elif os.name == "nt":
        os.system("cls")

while True:
    choice=""
    try:
        while choice.title() not in ["Server","Client","Credentials","1","2","3"]:
            Menu()
            choice=input("Enter your choice: ")
    except KeyboardInterrupt:
        print("\nGoodbye!\n")
        exit(1)
    if choice.title() in ["Server","1"]:
        Clear()
        try:
            Server()
        except:
            print("Unexpected Error:\n"+ str(sys.exc_info()[0]),"\n"+str(sys.exc_info()[1]))
    elif choice.title() in ["Client","2"]:
        Clear()
        try:
            Client()
        except:
            Clear()
            print("Unexpected Error:\n"+ str(sys.exc_info()[0]),"\n"+str(sys.exc_info()[1]))
    elif choice.title() in ["Credentials","3"]:
        PrintCustomerContents()
