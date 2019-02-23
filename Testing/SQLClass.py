import sqlite3
import time
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
                    kwargs["password"] = AESCipher.hasher(kwargs["password"]) # Turns the plaintext password into a database usable password
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
    def SearchMessages(self, username, SearchTerm=""):
        SearchTerm = "%"+SearchTerm+"%"
        if username == "*":
            databaseData = self.CommandDB("SELECT username, message FROM messages WHERE message LIKE ?",SearchTerm)
        else:
            databaseData = self.CommandDB("SELECT username, message FROM messages WHERE username = ? AND message LIKE ?",username, "%"+SearchTerm+"%")
        returnString=""
        for x in databaseData:
            returnString+="[{}]: {}\n".format(x[0],x[1])
        return returnString

DataBase = SQLDatabase("LoginCredentialsForTesting.db")
DataBase.CreateClientsTable()
DataBase.CreateBlockedTable()
DataBase.CreateMessageTable()
DataBase.dump("clients","blockedUsers","messages")
DataBase.AppendClientsDatabase("1.3.3.7",666,"Nick1","bcc014de6fb06f937156515b8f36fb2a995c037f441862411160f4b48f1ad602","Standard")
DataBase.AppendClientsDatabase("1.3.3.7",666,"Nick","bcc014de6fb06f937156515b8f36fb2a995c037f441862411160f4b48f1ad602","Admin")
DataBase.AddMessage("Nick1","Hey")
DataBase.AddMessage("Nick","There")
DataBase.AddMessage("Nick1","Test message")
DataBase.AddMessage("Nick","Characters?!")
DataBase.AddMessage("Nick1","Well well well")
print(DataBase.SearchMessages("Nick",SearchTerm="?"))
# print(DataBase.CommandDB("SELECT username, message FROM messages WHERE username = ? AND message LIKE ?","Nick1","%%"))
