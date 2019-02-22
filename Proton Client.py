# Notes:

# Background = #36393F
# Foreground = #484B51

# Imports

import socket, threading, base64, hashlib, pickle, os, sys, binascii, select, time, traceback, select, contextlib
from random import randint
with contextlib.redirect_stdout(None): # Imports pygame without printing version to terminal
    from pygame import mixer
# This imports a load of modules that are needed for the code to be run

def installModule(package):
    import subprocess
    import sys
    try:
        subprocess.call([sys.executable, "-m", "pip", "install", package])
        # Installs modules that are not default to python
    except:
        print("[!] Failed to install {}".format(package))

while 1:
    # The while loop makes sure the modules are installed, the first run will
    # see if the modules can be imported, if this fails then the module will
    # be installed, the loop will go around and then the modules are imported again
    try:
        import tkinter as tk
        from tkinter import ttk
        from tkinter import messagebox
        from tkinter import filedialog
        import tkinter.scrolledtext as tkst
        from Crypto import Random
        from Crypto.Cipher import AES
        break # Breaks here so that there is an end
        # This makes sure if the import fails, the module is installed
    except:
        print("[!] module is not installed, installing currently")
        installModule("tkinter")
        installModule("pycryptodome")
        # Installs modules if the import fails

# Global Variable declerations

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Sets up the socket for the connection to the server
initialAES = None
# Declares the encryption cipher

# Class declerations

class UserCredentials: # Class for storing credentials
    def __init__(self, username, password, createaccount):
        self.username = username
        self.password = password
        self.createaccount = createaccount

class AESCipher(object):
    def __init__(self, key):
        self.key = self.hasher(key)
        # Hashes a value and uses it as the cipher

    def hasher(self, password):
        salt = b'\xdfU\xc1\xdf\xf9\xb30\x96'
        # This is the default salt i am using for client and server side
        # Theoretically this should be random for each user and stored in the database
        return (  hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"), salt, 1000000)  )
        # Returns the hashed password using PBKDF2 HMAC

    def encrypt(self, raw):
        b64 = base64.b64encode(raw.encode("utf-8")).decode("utf-8")
        # Base 64 encoding using "UTF-8" encoding
        raw = self.pad(b64)
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
        try:
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
        except ValueError:
            print("[!] ValueError Occured")
        # Try except because not all data going into the fucntion is decryptable
        Decrypted = cipher.decrypt(enc[AES.block_size:])
        unpadded = self.unpad(Decrypted).decode("utf-8")
        # Decrypts and unpads the data
        Decoded = base64.b64decode(unpadded).decode("utf-8")
        return Decoded
        # Returns the decrypted data as a plaintext string

    def pad(self,s): # Pads the string so that it complys with the AES 16 byte block size
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)
        # Pads the data to a size of multiple 16

    def unpad(self, s): # Turns the 16 byte complyant string to a normal string
        return s[:-ord(s[len(s)-1:])]
        # Removes the padding from a string

# Functions

def sendMessage(cipher, message):
    encMessage = cipher.encrypt(message)
    try:
        sock.send(encMessage)
    except ConnectionResetError:
        print("Message could not be sent")
        messagebox.showerror("Message could not be sent","The connection to the server has been reset")

def recvMessage(cipher, *args):
    try:
        if not args:
            receaved = sock.recv(30000)
        else:
            receaved = sock.recv(args[0])
    except OSError:
        print("[!] {}".format(str(sys.exc_info()[1])))
        return False
    receaved = receaved.decode("utf-8")
    decrypted = cipher.decrypt(receaved)
    if len(decrypted) > 128:
        print("Receaved encrypted:",decrypted[:128],"of length {}".format(len(decrypted))) # For Debugging
    else:
        print("Receaved encrypted:",decrypted) # For Debugging
    return (decrypted)

def DH():
    # Exchanges a key with the server the client is connected to
    data = sock.recv(1024)
    data = data.decode("utf-8")
    data = data.split(" ")
    secret = randint(2**100, 2**150)
    # Creates a random private key
    sendkey = pow(int(data[0]), secret, int(data[1]))
    sock.send(bytes(str(sendkey),"utf-8"))
    key = pow(int(data[2]),int(secret),int(data[1]))
    return key

def DependancyDownloader(file, url):
    # Downloads the contents of a url to a file
    from urllib.request import urlopen
    data=urlopen(url).read()
    with open(file,"wb") as f:
        f.write(data)
    data="" # Stores a large amount of unnececary data in ram so it is cleared by this

class ProtonClient(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        # Inheritence from Tkinter's Tk class
        self.container = tk.Frame(self)
        # Makes a frame to store entries in
        if not os.path.isfile("ProtonDark.ico"):
            DependancyDownloader("ProtonDark.ico","https://raw.githubusercontent.com/TheDarthMole/ProtonChat/master/ProtonDark.ico")
        if not os.path.isfile("Notification.mp3"):
            DependancyDownloader("Notification.mp3","https://raw.githubusercontent.com/TheDarthMole/ProtonChat/master/Notification.mp3")
        # Used to download the icon from a server if it doesn't already exist (Required in order to run the code)
        tk.Tk.iconbitmap(self, default="ProtonDark.ico")
        self.container.pack(side="top", fill="both", expand= False)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)
        # Packing all the data onto the screen and resizing it
        self.frames = {}
        self.killThread = False

        for f in (StartConnect, MessagePage): # Add more pages in here to make them switchable
            frame = f(self.container, self)
            self.frames[f] = frame
            # Sets each custom class as a frame and stores in an array for later use
            frame.grid(row=0, column=0, sticky="nesw")
            # Sets the geometry of the class frames inside the container frame.

        self.showFrame(StartConnect)
        # Shows the first frame

    def showFrame(self, cont, **kwargs):
        frame = self.frames[cont]
        frame.tkraise()
        # Shows the frame defined in the parameter
        if cont == StartConnect:
            if "Disconnect" in kwargs and kwargs["Disconnect"]: # If the first statement is false,
                frame.DisconnectButtonPress()                    # the 2nd statement wont get run, therefore it wont thorw an error
                frame.configInterface("disabled")
        # Disables buttons to disconnect if the user has decided to logout
            self.geometry("235x300")
        elif cont == MessagePage:
            frame.StartThreaddedMessages() # Starts the threadding messaging manager
            frame.enterText.focus_set()
            frame.eventReturn("Enter")
            self.geometry("900x550")
        # Sets up the frame for display (size and the focus field)

class StartConnect(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.parent = parent
        self.controller = controller
        # So the class can reference the frame it is stored in
        self.connected = self.loggedIn = False
        # Variables used when the client disconnects
        tk.Frame.config(self,width=200, height=300) # Can edit background colour here
        self.label_title = ttk.Label(self, text = "Enter the Address and Port")
        self.label_title.grid(row=0, columnspan=2, pady=10)
        self.label_title.config(font="Helvetica 10")
        # Changes the font of the title
        self.label_address = ttk.Label(self, text="Address")
        self.label_port = ttk.Label(self, text="Port")
        self.default_address = tk.StringVar(self, "127.0.0.1") # Completely for time efficiency, delete after testing
        self.default_port = tk.StringVar(self, "65528")        # however could be used for a default Server
        self.entry_address = tk.Entry(self, textvariable = self.default_address)
        # textvariable = self.default_address used for testing, time effective
        # Sets up the address and port of the login fields
        self.entry_port = tk.Entry(self, textvariable = self.default_port)
        self.label_address.grid(row=1, pady=3)
        self.label_port.grid(row=2, pady=3)
        self.entry_address.grid(row=1, column=1, pady=3, padx=11)
        self.entry_port.grid(row=2, column=1, pady=3, padx=11)
        # Places the entry fields onto the screen
        self.button_connect = ttk.Button(self, text="Connect", command=self.ConnectButtonPress)
        self.button_connect.grid(row=3, padx=7, pady=5)
        # Creates the connect button and places it on the screen
        self.button_disconnect = ttk.Button(self, text="Disconnect", command=self.DisconnectButtonPress, state="disabled")
        self.button_disconnect.grid(row=3, column=1, columnspan=1)
        # Creates the disconnect button and places it on the screen
        self.label_connIndicator = ttk.Label(self, text="Current Status: Disconnected\n")
        self.label_connIndicator.grid(row=4, columnspan=2)
        # Creates a indicator label to update the user on the connection status, then places it on the screen
        self.CheckVar = tk.IntVar(value=0)
        self.checkbox_createAccount = ttk.Checkbutton(self, text="Create new account", variable = self.CheckVar, state = "disabled")
        self.checkbox_createAccount.grid(row=5, columnspan=2)
        # Creates the checkbox to create the account and places it on the screen
        self.label_username = ttk.Label(self, text="Username")
        self.label_password = ttk.Label(self, text="Password")
        self.entry_username = ttk.Entry(self, state="disabled") # Disabled because you can't login before connecting
        self.entry_password = ttk.Entry(self, state="disabled", show="*")
        # Creates username and password entry fields, with corresponding labels
        self.label_username.grid(row=6)
        self.label_password.grid(row=7)
        self.entry_username.grid(row=6, column=1, pady=3)
        self.entry_password.grid(row=7, column=1, pady=3)
        # Places the entry fields and labels on the screen
        self.button_login = ttk.Button(self, text="Login", command= lambda: self.LoginButtonPress(controller), state="disabled")
        self.button_login.grid(columnspan=2, padx=5, pady=5)
        # Creates the login button and places it on the screen, it calls the login function
        self.button_nextpage = ttk.Button(self, text="Next Page", state="disabled", command=lambda: controller.showFrame(MessagePage))
        self.button_nextpage.grid(columnspan=2, padx=5, pady=5)
        # Creates a button to switch to the next page then places it on the screen
        self.place(relx=0.5, rely=0.5, anchor="center")
        # Smacks all of the contents of this custom frame into the "container" frame

    def DisconnectButtonPress(self):
        global sock
        sock.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Closes the socket and resets it
        self.label_connIndicator.config(text="Current Status: Disconnected\n")
        self.entry_username.config(state="disabled")
        self.entry_password.config(state="disabled")
        self.checkbox_createAccount.config(state="disabled")
        self.button_disconnect.config(state="disabled")
        self.button_connect.config(state="normal")
        self.button_nextpage.config(state="disabled")
        self.button_login.config(state="disabled")
        # Disables buttons that should not be pressed once the user is disconnected
        self.controller.killThread = True
        # Tells the threadded function to stop running

    def ConnectButtonPress(self):
        global sock
        address = self.entry_address.get()
        port = self.entry_port.get()
        # Grabs the data from the entry fields and stores in variables
        try: # In this try because the connection may fail
            continueconnect = False
            sock.connect((address, int(port))) # Connect to the server
            print("Connected!")
            continueconnect = True
            # If the connection fails, "continueconnect" wont be set to True
        except socket.gaierror:
            messagebox.showerror("Failed to connect!","The ip or port is not valid")
            return
            # Returns if the ip or port of the server is invalid
        except TimeoutError:
            messagebox.showerror("Failed to connect!","The connection was refused or the host did not respond")
            return
            # Shows and error and returns out of the funciton if the host doenst respond
        except OSError as e:
            messagebox.showerror("Failed to connect!",e)
            return
            # Shows and error and returns out of the function if an error that is not known occurs
        except ValueError:
            messagebox.showerror("Failed to connect!","You entered an incorrect port number (It has to be a number)")
            return
            # Shos and error and returns out of the function if a letter is entered in as ip or port
        finally:
            if not continueconnect:
                sock.close()
                # Closes the connection if ordered to close the connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # Resets the socket
        try: # In a try loop because the connection may close
            global DiffieHellman
            global initialAES
            DiffieHellman = DH()
            # We have created a diffie-hellman key exchange here, used for initialAES encryption
            initialAES = AESCipher(hex(int(DiffieHellman)))
            # Setting the diffie-hellman key as the key for AES
            print(recvMessage(initialAES))
            # Prints a message saying the cipher works (Is sent by the server then Decrypted
            # meaning if the cipher doesnt work then the text will look like ciphertext)
            self.label_connIndicator.config(text="Current Status: Connected!\n            Please Log in")
            self.entry_username.config(state="normal")
            self.entry_password.config(state="normal")
            self.checkbox_createAccount.config(state="normal")
            self.button_login.config(state="normal")
            self.button_disconnect.config(state="normal")
            self.button_connect.config(state="disabled")
            # Enables and disables buttons and text fields once the user has connected
        except ConnectionResetError:
            # ConnecionResetError is if the user closes the connection mid way through the connection
            print("[x] Connection with",address+":"+str(port),"was actively closed")
            messagebox.showerror("Connection lost!",("Connection with "+address+":"+str(port)+" was actively closed."))
            # Displays a popup saying the connection was lost
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Disconnects from the server then resets the socket
        except ValueError:
            messagebox.showerror("Connected to wrong server!","You have connected to a server that is not running Proton Server.")
            # Displays a message saying the user has connected to a server, but it doesn't run the correct backend code
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Disconnects the socket and then resets it

    def configInterface(self, value):
        for x in (self.entry_username, self.entry_password,self.checkbox_createAccount,self.button_login, self.button_disconnect, self.button_nextpage):
            x.config(state=value)
            # Disables/Enables a set of buttons and entries dependant on the "value" parameter
        if value == "disabled":
            self.button_login.config(state="active")
            # Inverts the login button based on the "value" parameter
        else:
            self.button_login.config(state="disabled")
            # Else it is set to disabled

    def LoginButtonPress(self, controller):
        username = self.entry_username.get()
        password = self.entry_password.get()
        # Retrieves the username and password data from the entry fields
        password = initialAES.hasher(password).hex()
        # Hashes the password and turns it into hex
        createaccount = self.CheckVar.get()
        # Gets the value of the checkbox and saves it as a "1" or "0"
        tosend = UserCredentials(username,password,True if createaccount else False)
        # Saves "tosend" as an instance of "UserCredentials"
        # UserCredentials litterally just stores the parameters as instance variables
        self.UserCredentials = tosend
        # Saves the data as an instance variable
        tosend = pickle.dumps(tosend).hex()
        # Turns the class into bytes, therefore sendable over Sockets
        sendMessage(initialAES,tosend)
        # Sends the UserCredentials class pickled, hexified then encrypted to server
        self.loggedIn=False

        message = recvMessage(initialAES)
        if message[:3] == "ASC":
            # "ASC" is Account Successfully Created
            self.loggedIn = True
            messagebox.showinfo("Account Created","You have successfully created an account!")
            # Displays a info box saying the account has been created
            self.button_login.config(state="disabled")
            self.button_nextpage.config(state="active")
            # Sets the login button to enables and disables the next page button to disabled
            controller.showFrame(MessagePage)
            # Shows the "MessagePage" frame
        elif message[:3] == "SLI":
            # "SLI" is Successfully Logged In
            self.loggedIn = True
            messagebox.showinfo("Login Successful","You have successfully logged in!")
            # Displays a message saying the user logged in successfully
            self.button_login.config(state="disabled")
            self.button_nextpage.config(state="active")
            # Disables and enables the respective Login and nextpage button
            controller.showFrame(MessagePage)
            # Shows the "MessagePage" frame
        elif message[:3] == "ERR":
            # "ERR" stands for Error
            messagebox.showerror("An error occured", message[4:])
            # An unknown error has occured, the error is then displayed to the user
        elif message[:3] == "LAE":
            # "LAE" stands for Login Attempts Exceeded
            self.configInterface("disabled")
            self.DisconnectButtonPress()
            # Disables a load of buttons, forces the user to disconnect from the server
            messagebox.showerror("Login credentials rejected","You have entered incorrect credentials too many times.")
            # Displays an error message saying the user has logged in too many times

class MessagePage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        # Inherits from Tk.Frame, Tkinter module
        parent.focus_set()
        # Sets the focus on the parent frame; Detection for hitting "Enter" is detected
        self.parent = parent
        self.controller=controller
        # Sets the parent frame as an instance variable
        self.grid_columnconfigure(0,weight=1)
        self.grid_rowconfigure(0,weight=1)
        # "MessagePage" is essentially a frame, so it sets its own "Weight" to 1
        # This means that the message page can be resized, and the frame will stick to the outside of the container
        self.uiMessages = tkst.ScrolledText(self, state="disabled", height=128)
        # Scrollable text field means the data from the server can be displayed to the user
        # It is disabled so the user cannot enter their own data, but data can be entered by the program
        self.enterText = tk.Text(self, width=32, height=2)
        self.backButton = ttk.Button(self, text="Back", command = self.returnButton)
        self.sendButton = ttk.Button(self, text="Send", command = self.eventReturn)
        self.uploadButton = ttk.Button(self, text="Upload", command = self.upload)
        # Text field for message entry and buttons to call functions are created
        self.uiMessages.grid(row=0, sticky="NESW", columnspan=2)
        self.enterText.grid(row=1, column=0,sticky="NESW")
        self.backButton.grid(row=2, column=0, sticky="WS")
        self.sendButton.grid(row=1, column=1,sticky="E")
        self.uploadButton.grid(row=2, column=0, sticky="ES")
        # Places the buttons and text fields onto the screen, sticking them to different sides of the container
        self.sendingFiles = False
        self.onScreen = False
        self.threadStarted = False
        self.addAdminMessage("Welcome to Proton Messenger, use '/Help' for commands","Server") # Welcome message
        controller.bind("<Return>",self.eventReturn)
        # Binds "Enter" to run the eventReturn function (Sends a text message to the server)

    def StartThreaddedMessages(self, *char):
        if not self.threadStarted:
            # Starts a thread to listen for messages from the server
            self.onScreen=True
            self.threadStarted = True
            self.MessageThread = threading.Thread(target=self.FetchMessages)
            # Creates a thread instance
            self.MessageThread.daemon=True
            # Sets the thread to close when the main program closes
            self.MessageThread.start()
            # Starts the thread
            print("Another thread started!")

    def SwitcherMSG(self,*args):
        todisplay = args[0].split("|")
        # Splits the data entered into the function by the symbol "|"
        if todisplay[2] == "Standard":
            self.addMessage("|".join(todisplay[3:]),todisplay[1])
            # Displays the message from the user using a blue message headder
            # Indicates the message was sent by a standard user
        else:
            self.addAdminMessage("|".join(todisplay[3:]),todisplay[1])
            # Displays the message from the user using a read message headder
            # Indicates the message was sent by an admin

    def SwitcherFileNotFound(self, *args):
        # Args is used because data is passed into all fucntions of the Switcher
        # As it is easier to call different functions that way
        self.addAdminMessage("The file was not found","Server")
        # Displays a message from the server saying the file was not found

    def KeyError(self, *args):
        # This function is run when an incorrect command is called
        # *args is the whole command
        data = args[0].split("|")
        # Splts up the string into an array with "|" being the splitter
        self.addAdminMessage("{} is not a valid command".format(" ".join(data[1:])), "Server")
        # Displays a message from the server saying the command entered is not valid

    def FetchMessages(self):
        self.unbind("<Enter>")
        # Stops the FetchMessages fucntion from being called when the mouse enteres the screen
        # This was setup previously in another function
        self.switcher = {
        "Msg": self.SwitcherMSG,
        "Filedownload": self.download,
        "Fnf": self.SwitcherFileNotFound,
        "Keyerror": self.KeyError,
        "Logout": self.logout}
        # These are the server side commands that can be sent to the client
        ready = select.select([sock], [], [], 5)
        # "ready" is used to see when there is data to accept from the server
        print("FetchMessages running")
        while 1: # This fucntion does have exit perameters, however they are checked throughout the loop
            if self.controller.killThread:
                self.controller.killThread = False
                self.threadStarted = False
                # Tells other functions to stop running the thread
                return
            if not self.sendingFiles:
                if ready[0]:
                    # If there is data to recieve:
                    data = recvMessage(initialAES)
                    if type(data) == type(False) and data == False:
                        # Checks to make sure the data sent is not invalid
                        self.controller.killThread = False
                        self.threadStarted = False
                        return # If the data couldn't be collected because the socket is closed
                    data1 = data.split("|")
                    command = data1[0].title()
                    # Turns the data back into an array, e.g. ["MSG","Nick","Hey there!"]
                    if command in self.switcher:
                        self.switcher[command](data)
                        # If the command is in the list of correct commands, then the command will be run
                    else:
                        self.addAdminMessage("'{}' is not a valid command".format(command), "Server")
                        # If the comand is not in the avaliable commands then an error is displayed
        print("BROKE OUT OF THE LOOP!!!")

    def upload(self, *args):
        self.sendingFiles = True
        # Set to true so that other data recieved by the thread is not written to the file
        print("Uploading data!")
        filepath = filedialog.askopenfilename(title = "Select a file to upload",filetypes = (("All Files","*.*"),))
        # Opens a dialog box to select a file from storage
        if not filepath:
            self.addAdminMessage("No file was selected","Server")
            # If no file path is selected:
            self.sendingFiles = False
            return # Return means there is no need for an "else" statement, as fucntion closes anyway
        filename = filepath.split("/")
        filename = filename[-1]
        # Grabs the filename from the whole path, e.g. "C:/Proton/Image.png", "Image.png" will be the filename
        if os.path.isfile(filepath):
            # If the file exists:
            print("Sending '{}' to Server".format(filename))
            with open(filepath,"rb") as f:
                # Opens the file and reads the raw bytes
                encDataToSend = binascii.hexlify(f.read(os.path.getsize(filepath))).decode("utf-8")
                encDataToSend = initialAES.encrypt(encDataToSend)
                # Reads the whole contents of the file and stores it in memory
                # The file is then turned into hex so that it can be encrypted using the cipher
            sendMessage(initialAES,"Uploading|{}|{}".format(filename,str(len(encDataToSend))))
            # A message is then sent to the server displaying that the client wants to upload a file
            # The message also includes how big the file is and its name, so the data can be read exactly
            # and saved to a file on the server
            fileOnServer = recvMessage(initialAES)
            # Gets a response from the server, either accepting the file or rejecting it
            if fileOnServer == "FAE":
                # "FAE" stands for "File Already Exists"
                print("File is already on the server")
                self.addAdminMessage("A file by that name already exists on the server!","Server")
                self.sendingFiles=False
                return
                # The file cannot be sent, therefore the function quits.
                # As this function is event based, it can elegantly quit and be called again on another event call
            time.sleep(1)
            # Sleeps for 1ms, this is due to an error that I was seeing
            sock.send(encDataToSend)
            # Sends the encrypted file to the server
            print("Sent file!")
            self.addAdminMessage("File uploaded to server","Server")
            # Display a message stating the file has been sent
        else:
            print("File is not there!")
            self.addAdminMessage("You did not select a valid file!","Server")
            # If the file was not found, then the client will display a message to the user
            sendMessage(initialAES,"FNF")
            # "FNF" stands for "File Not Found"
        self.sendingFiles = False
        # Sets to false so that other messages can be recieved from the server

    def download(self, data):
        self.sendingFiles = True
        # Stops other messages from being sent to the client
        print("Downloading data!")
        split = data.split("|")
        filename = split[1]
        # Gets the filename from an array passed into the function
        print("Started download of {}".format(filename))
        self.addAdminMessage("Downloading '{}''".format(filename),"Server")
        # Notifies the user of the file being downloaded
        filesize = int(split[2])
        f = open("new_"+filename,"wb")
        # Creates a file for the data to be written to (Writing the data in raw bytes)
        data = recvMessage(initialAES)
        # Recieve the filesize
        encrypted = recvMessage(initialAES,int(data))
        # Recieve the encrypted file
        decoded = binascii.unhexlify(encrypted)
        # Turns the hex string into bytes
        f.write(decoded)
        # Writes the data to the file
        print("Done downloading!")
        self.addAdminMessage("Downloaded '{}' as 'new_{}'".format(filename, filename),"Server")
        # Notifies the user of the successful download
        self.sendingFiles = False
        # Allows other commands to be recieved

    def eventReturn(self, *event):
        if app.frames[StartConnect].loggedIn:
            # If the user is logged in
            text = self.enterText.get("1.0","end")
            text = text.rstrip("\n")
            self.enterText.delete("1.0", "end")
            if not text:
                return
                # Returns if there is nothing in the text field
            if text and text[0] == "/": # 'If text' is a quick check to see if there is data to manipulate
                tosend = text.split(" ")
                last = text.lstrip(tosend[0])
                last = last.lstrip(" ")
                sendMessage(initialAES, tosend[0]+"|"+last)
                # If it is a command, then the structure is different than if it was a message
            else:
                self.addOwnMessage(text)
                sendMessage(initialAES, "MSG|"+text)
                # If the data is a message, then send it in the structure of a message
        else:
            app.frames[StartConnect].LoginButtonPress(self.controller)
            # The user is not logged in in this stage, so it tries to log them in

    def logout(self,*args):
        self.controller.showFrame(StartConnect,Disconnect=True)
        # Logs out the user, and then disconnects them from the server

    def NotificationSound(self):
        mixer.init()
        mixer.music.load("Notification.mp3")
        mixer.music.play()
        # Plays a notification sound using the "Notification.mp3" dependancy

    def returnButton(self):
        self.onScreen = False
        self.controller.showFrame(StartConnect)
        # Shows the "StartConnect" frame

    def addText(self, text): # Adds text to the end of the scrollable text
        self.uiMessages.config(state="normal")
        self.uiMessages.insert("end",chars=str(text)+"\n")
        self.uiMessages.config(state="disabled")
        # Adds text to the messenger interface

    def addMessage(self, text, recipient):
        self.NotificationSound()
        self.uiMessages.config(state="normal")
        self.uiMessages.insert("end",chars=str("["+recipient+"] ")+str(text)+"\n")
        lastLine = int(self.uiMessages.index('end-1c').split('.')[0]) - 1
        # Adds some text to the messenger interface
        self.uiMessages.tag_add("red", str(lastLine - len(text.splitlines())+1)+".0",str(lastLine - len(text.splitlines())+1)+"."+str(len(recipient)+2))
        self.uiMessages.tag_config("red", foreground = "red")
        # Turns the name of the user to red
        self.uiMessages.see("end")
        self.uiMessages.config(state="disabled")
        # Disables the text field so users cant enter data

    def addAdminMessage(self, text, recipient):
        self.NotificationSound()
        # Plays a notification sound
        self.uiMessages.config(state="normal")
        self.uiMessages.insert("end",chars=str("["+recipient+"] ")+str(text)+"\n")
        # Adds a message to the messenger interface
        lastLine = int(self.uiMessages.index('end-1c').split('.')[0]) - (2 if len(text.splitlines())>1 else 1)
        self.uiMessages.tag_add("blue", str(lastLine - len(text.splitlines())+1)+".0",str(lastLine - len(text.splitlines())+1)+"."+str(len(recipient)+2))
        self.uiMessages.tag_config("blue", foreground = "blue")
        # Some very ugly code that turns the name of the user to blue; indicating the user is an admin
        self.uiMessages.see("end")
        self.uiMessages.config(state="disabled")
        # Disables the text field so users cant enter data

    def addOwnMessage(self, text):
        self.NotificationSound()
        # Plays a notification sound
        self.uiMessages.config(state="normal")
        self.uiMessages.insert("end",chars=str("[Me] ")+str(text)+"\n")
        # Adds a message to the messenger interface
        lastLine = int(self.uiMessages.index('end-1c').split('.')[0]) - (2 if len(text.splitlines())>1 else 1)
        self.uiMessages.tag_add("green", str(lastLine - len(text.splitlines())+1)+".0",str(lastLine - len(text.splitlines())+1)+"."+str(4))
        self.uiMessages.tag_config("green", foreground = "green")
        # Some very ugly code that turns the name of the user to blue; indicating the user is an admin
        self.uiMessages.see("end")
        self.uiMessages.config(state="disabled")
        # Disables the text field so users cant enter data

if __name__ == "__main__":
    try:
        # Try and except so the program can be closed with CTRL-C
        app = ProtonClient()
        # Starts the tkinter interface
        app.title("Proton Client")
        # Sets the title for the windows window
        app.mainloop()
        # Shows where the tkinter code should loop through
    except KeyboardInterrupt:
        print("KeyboardInterrupt occured, quitting")
        # Notifies the user why the program closed
    finally:
        sock.close()
        # Elegantly closes the socket so that it doesn't stay open
