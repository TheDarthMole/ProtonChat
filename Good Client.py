import socket, threading, base64, hashlib, pickle, os, sys, binascii
from random import randint
from Crypto import Random
from Crypto.Cipher import AES

# Notes:

# Background = #36393F
# Foreground = #484B51

try:
    import tkinter as tk
    from tkinter import ttk
    from tkinter import messagebox
    from tkinter import filedialog
    import tkinter.scrolledtext as tkst
except:
    print("[!] tkinter module is not installed, install using cmd 'py -m pip install tkinter'")
    exit(0)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
BreakConnection = False

# Diffie-hellman key declerations
publicPrime = None
publicBase = None
privateKey = None
cipherKey = None
# Encryption declerations
initialAES = None
finalAES = None

# Class declerations

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
        b64 = base64.b64encode(raw.encode("utf-8")).decode("utf-8")
        raw = self.pad(b64)
        rawbytes = bytes(raw,"utf-8")
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(rawbytes))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        try:
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
        except ValueError:
            print("[!] ValueError Occured")
        Decrypted = cipher.decrypt(enc[AES.block_size:])
        unpadded = self.unpad(Decrypted).decode("utf-8")
        Decoded = base64.b64decode(unpadded).decode("utf-8")
        return Decoded
        #return base64.b64decode(self.unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')).decode("utf-8")

    def pad(self,s): # Pads the string so that it complys with the AES 16 byte block size
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    def unpad(self, s): # Turns the 16 byte complyant string to a normal string
        return s[:-ord(s[len(s)-1:])]

# Functions

def getLocalIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80)) # 8.8.8.8 is Googles DNS server; its an ip not going to change anytime
    except:
        s.connect(("1.1.1.1",80)) # Cloudflare DNS Resolver project IP, another host that won't change soon
    return s.getsockname()[0] # Returns the local ip of the internet facing NIC adapter (This makes sure the local ip of a virtual adapter is not taken)

def sendMessage(cipher, message):
    encMessage = cipher.encrypt(message)
    try:
        sock.send(encMessage)
    except ConnectionResetError:
        messagebox.showerror("Message could not be sent","The connection to the server has been reset")

def recvMessage(cipher, *args):
    if not args:
        receaved = sock.recv(30000)
    else:
        receaved = sock.recv(args[0])
    receaved = receaved.decode("utf-8")
    decrypted = cipher.decrypt(receaved)
    if len(decrypted) > 128:
        print("Receaved encrypted:",decrypted[:128],"of length {}".format(len(decrypted))) # For Debugging
    else:
        print("Receaved encrypted:",decrypted) # For Debugging
    return (decrypted)

def DH():
    data = sock.recv(1024)
    data=data.decode("utf-8")
    data = data.split(" ")
    secret = randint(2**100, 2**150)
    sendkey = pow(int(data[0]), secret, int(data[1]))
    sock.send(bytes(str(sendkey),"utf-8"))
    key = pow(int(data[2]),int(secret),int(data[1]))
    return key

class ProtonClient(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        container = tk.Frame(self)
        tk.Tk.iconbitmap(self, default="ProtonDark.ico")
        container.pack(side="top", fill="both", expand= False)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        self.frames = {}

        for f in (StartConnect, MessagePage): # Add more pages in here to make them switchable
            frame = f(container, self)
            self.frames[f] = frame
            frame.grid(row=0, column=0, sticky="nesw")

        self.showFrame(StartConnect)

    def showFrame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()

class StartConnect(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.parent = parent
        #self.config(bg="#36393E")
        self.connected = False
        self.loggedIn=False
        tk.Frame.config(self,width=200, height=300) # Can edit background colour here
        self.label_title = ttk.Label(self, text = "Enter the Address and Port")
        self.label_title.grid(row=0, columnspan=2, pady=10)
        self.label_title.config(font="Helvetica 10")

        self.style = ttk.Style()
        self.style.configure("ProtonStyle.TEntry", background = "#36393F")
        self.style.map("ProtonStyle.TEntry",
                            foreground=[("disabled","grey"),
                                        ("active","#484B51")],
                            background=[("disabled","grey"),
                                        ("active","#36393F")])

        self.label_address = ttk.Label(self, text="Address")
        self.label_port = ttk.Label(self, text="Port")
        self.default_address = tk.StringVar(self, "127.0.0.1") # Completely for time efficiency, delete after testing
        self.default_port = tk.StringVar(self, "65528")        # however could be used for a default Server
        self.entry_address = tk.Entry(self, textvariable = self.default_address) # textvariable = self.default_address used for testing, time effective
        self.entry_port = tk.Entry(self, textvariable = self.default_port)
        self.label_address.grid(row=1, pady=3)
        self.label_port.grid(row=2, pady=3)
        self.entry_address.grid(row=1, column=1, pady=3, padx=11)
        self.entry_port.grid(row=2, column=1, pady=3, padx=11)
        self.button_connect = ttk.Button(self, text="Connect", command=self.ConnectButtonPress)
        self.button_connect.grid(row=3, padx=7, pady=5)
        self.button_disconnect = ttk.Button(self, text="Disconnect", command=self.DisconnectButtonPress, state="disabled")
        self.button_disconnect.grid(row=3, column=1, columnspan=1)
        self.label_connIndicator = ttk.Label(self, text="Current Status: Disconnected\n")
        self.label_connIndicator.grid(row=4, columnspan=2)
        self.CheckVar = tk.IntVar(value=0)
        self.checkbox_createAccount = ttk.Checkbutton(self, text="Create new account", variable = self.CheckVar, state = "disabled")
        self.checkbox_createAccount.grid(row=5, columnspan=2)
        self.label_username = ttk.Label(self, text="Username")
        self.label_password = ttk.Label(self, text="Password")
        self.entry_username = ttk.Entry(self, state="disabled") # Disabled because you can't login before connecting
        self.entry_password = ttk.Entry(self, state="disabled", show="*")
        self.label_username.grid(row=6)
        self.label_password.grid(row=7)
        self.entry_username.grid(row=6, column=1, pady=3)
        self.entry_password.grid(row=7, column=1, pady=3)
        self.button_login = ttk.Button(self, text="Login", command= lambda: self.LoginButtonPress(controller), state="disabled")
        self.button_login.grid(columnspan=2, padx=5, pady=5)
        self.button_nextpage = ttk.Button(self, text="Next Page", command=lambda: controller.showFrame(MessagePage))
        self.button_nextpage.grid(columnspan=2, padx=5, pady=5)

        self.place(relx=0.5, rely=0.5, anchor="center")

    def DisconnectButtonPress(self):
        global sock
        sock.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.label_connIndicator.config(text="Current Status: Disconnected\n")
        self.entry_username.config(state="disabled")
        self.entry_password.config(state="disabled")
        self.checkbox_createAccount.config(state="disabled")
        self.button_disconnect.config(state="disabled")
        self.button_connect.config(state="normal")

    def ConnectButtonPress(self):
        global sock
        address = self.entry_address.get()
        port = self.entry_port.get()
        try:
            continueconnect = False
            sock.connect((address, int(port))) # Connect to the server
            print("Connected!")
            continueconnect = True
        except socket.gaierror:
            messagebox.showerror("Failed to connect!","The ip or port is not valid")
            return
        except TimeoutError:
            messagebox.showerror("Failed to connect!","The connection was refused or the host did not respond")
            return
        except OSError as e:
            messagebox.showerror("Failed to connect!",e)
            return
        except ValueError:
            messagebox.showerror("Failed to connect!","You entered an incorrect port number (It has to be a number)")
            return
        finally:
            if not continueconnect:
                sock.close()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            global DiffieHellman
            DiffieHellman = DH() # We have created a diffie-hellman key exchange here, used for initialAES encryption
            global initialAES
            initialAES = AESCipher(hex(int(DiffieHellman))) # Setting the diffie-hellman key as the key for AES
            print(recvMessage(initialAES))
            self.label_connIndicator.config(text="Current Status: Connected!\n            Please Log in")
            self.entry_username.config(state="normal")
            self.entry_password.config(state="normal")
            self.checkbox_createAccount.config(state="normal")
            self.button_login.config(state="normal")
            self.button_disconnect.config(state="normal")
            self.button_connect.config(state="disabled")
        except ConnectionResetError:
            print("[x] Connection with",address+":"+str(port),"was actively closed")
            messagebox.showerror("Connection lost!",("Connection with "+address+":"+str(port)+" was actively closed."))
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except ValueError:
            messagebox.showerror("Connected to wrong server!","You have connected to a server that is not running Proton Server.")
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def LoginButtonPress(self, controller):
        username = self.entry_username.get()
        password = self.entry_password.get()
        password = initialAES.hasher(password).hex()
        createaccount = self.CheckVar.get()
        if createaccount == 1:
            createaccount = True
        else:
            createaccount = False
        tosend = UserCredentials(username,password,createaccount)
        self.UserCredentials = tosend
        tosend = pickle.dumps(tosend).hex() # Turns the class into bytes, therefore sendable over Sockets
        sendMessage(initialAES,tosend) # Sends the UserCredentials class pickled, hexified then encrypted to server
        self.loggedIn=False

        message = recvMessage(initialAES)
        if message[:3] == "ASC":
            self.loggedIn = True
            messagebox.showinfo("Account Created","You have successfully created an account!")
            self.button_login.config(state="disabled")
            controller.showFrame(MessagePage)
        elif message[:3] == "SLI":
            self.loggedIn = True
            messagebox.showinfo("Login Successful","You have successfully logged in!")
            self.button_login.config(state="disabled")
            controller.showFrame(MessagePage)
        elif message[:3] == "ERR":
            messagebox.showerror("An error occured", message[4:])

class MessagePage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        parent.focus_set()
        self.parent = parent
        self.controller=controller
        tk.Frame.config(self,width=100, height=300)
        self.uiMessages = tkst.ScrolledText(self, state="disabled")
        self.enterText = tk.Text(self, width=32, height=2)
        self.backButton = ttk.Button(self, text="Back", command=self.returnButton)
        self.uploadButton = ttk.Button(self, text="Upload", command = lambda: self.upload())
        self.uiMessages.grid(row=0, sticky="EW")
        self.enterText.grid(row=1, column=0)
        self.backButton.grid(row=2, column=0, sticky="W")
        self.uploadButton.grid(row=2, column=0, sticky="E")
        self.sendingFiles = False
        #help(tkst.ScrolledText)
        self.addText("Text added")
        self.addText("Other text")
        self.addMessage("Text","Nick") # Testing stuff
        self.addAdminMessage("AdminText","Admin")
        controller.bind("<Return>",self.eventReturn)
        self.bind("<Enter>",self.StartThreaddedMessages)

    def StartThreaddedMessages(self, char):
        self.onScreen=True
        self.MessageThread = threading.Thread(target=self.FetchMessages)
        self.MessageThread.daemon=True
        self.MessageThread.start()
    def SwitcherMSG(self,*args):
        todisplay = args[0].split("|")
        if todisplay[2] == "Standard":
            self.addMessage("|".join(todisplay[3:]),todisplay[1])
        else:
            self.addAdminMessage("|".join(todisplay[3:]),todisplay[1])
    def SwitcherFileNotFound(self, *args):
        self.addAdminMessage("The file was not found","Server")

    def KeyError(self, *args):
        data = args[0].split("|")
        self.addAdminMessage("{} is not a valid command".format(" ".join(data[1:])), "Server")

    def FetchMessages(self):
        self.unbind("<Enter>")
        self.switcher = {
        "Msg": self.SwitcherMSG,
        "Filedownload": self.download,
        "Fnf": self.SwitcherFileNotFound,
        "Keyerror": self.KeyError}
        while 1:
            if self.onScreen and not self.sendingFiles:
                data = recvMessage(initialAES)
                data1 = data.split("|")
                command = data1[0].title()
                if command in self.switcher:
                    self.switcher[command](data)
                else:
                    self.addAdminMessage("'{}' is not a valid command".format(command), "Server")

    def upload(self, *args):
        print("Uploading data!")
        filepath = filedialog.askopenfilename(title = "Select a file to upload",filetypes = (("All Files","*.*"),))
        if not filepath:
            self.addAdminMessage("No file was selected","Server")
            return
        filename = filepath.split("/")
        print("FilePath:",filepath)
        filename = filename[-1]
        print("File Name:",filename)
        if os.path.isfile(filepath):
            print("Sending '{}' to Server".format(filepath.split("/")[-1]))
            with open(filepath,"rb") as f:
                encDataToSend = binascii.hexlify(f.read(os.path.getsize(filepath))).decode("utf-8")
                encDataToSend = initialAES.encrypt(encDataToSend)
            print(type(filename))
            print(filename)
            sendMessage(initialAES,"Uploading|{}|{}".format(filename,str(len(encDataToSend))))
            print("Sent Uploading message")
            sock.send(encDataToSend)
        else:
            print("File is not there!")
            sendMessage(initialAES,"FNF")

    def download(self, data):
        self.sendingFiles = True
        print("Downloading data!")
        split = data.split("|")
        filename = split[1]
        print("Started download of {}".format(filename))
        self.addAdminMessage("Downloading '{}''".format(filename),"Server")
        filesize = int(split[2])
        f = open("new_"+filename,"wb")
        data = recvMessage(initialAES)
        encrypted = recvMessage(initialAES,int(data))
        decoded = binascii.unhexlify(encrypted)
        f.write(decoded)
        print("Done downloading!")
        self.addAdminMessage("Downloaded '{}' as 'new_{}'".format(filename, filename),"Server")
        self.sendingFiles = False

    def eventReturn(self, event):
        #print("Return pressed", repr(event.char))
        if app.frames[StartConnect].loggedIn:
            text = self.enterText.get("1.0","end")
            text = text.rstrip("\n")
            self.enterText.delete("1.0", "end")
            if not text:
                return
            if text and text[0] == "/": # 'If text' is a quick check to see if there is data to manipulate
                tosend = text.split(" ")
                last = text.lstrip(tosend[0])
                last = last.lstrip(" ")
                print(tosend[0]+"|"+last)
                sendMessage(initialAES, tosend[0]+"|"+last)
            else:
                sendMessage(initialAES, "MSG|"+text)
        else:
            app.frames[StartConnect].LoginButtonPress(self.controller)
    def returnButton(self):
        self.onScreen = False
        self.controller.showFrame(StartConnect)
    def addText(self, text): # Adds text to the end of the scrollable text
        self.uiMessages.config(state="normal")
        self.uiMessages.insert("end",chars=str(text)+"\n")
        self.uiMessages.config(state="disabled")
    def addMessage(self, text, recipient):
        self.uiMessages.config(state="normal")
        self.uiMessages.insert("end",chars=str("["+recipient+"] ")+str(text)+"\n")
        lastLine = int(self.uiMessages.index('end-1c').split('.')[0]) - 1
        self.uiMessages.tag_add("red", str(lastLine)+".0",str(lastLine)+"."+str(len(recipient)+2))
        self.uiMessages.tag_config("red", foreground = "red")
        self.uiMessages.see("end")
        self.uiMessages.config(state="disabled")
    def addAdminMessage(self, text, recipient):
        self.uiMessages.config(state="normal")
        self.uiMessages.insert("end",chars=str("["+recipient+"] ")+str(text)+"\n")
        lastLine = int(self.uiMessages.index('end-1c').split('.')[0]) - 1
        self.uiMessages.tag_add("blue", str(lastLine)+".0",str(lastLine)+"."+str(len(recipient)+2))
        self.uiMessages.tag_config("blue", foreground = "blue")
        self.uiMessages.see("end")
        self.uiMessages.config(state="disabled")
    def addOwnMessage(self, text, recipient):
        pass
if __name__ == "__main__":
    try:
        app = ProtonClient()
        app.title("Proton Client")
    #    app.config(bg="#36393E")
        app.mainloop()
    except KeyboardInterrupt:
        print("KeyboardInterrupt occured, quitting")
    finally:
        sock.close()
