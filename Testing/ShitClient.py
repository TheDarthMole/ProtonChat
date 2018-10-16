import socket
from random import randint
host="127.0.0.1"
port=65530
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect( (host, port))
def DH():
    data = sock.recv(1024)
    data=data.decode("utf-8")
    data = data.split(" ")
    print(data)
    secret = randint(2**100, 2**150)
    sendkey = pow(int(data[0]), secret, int(data[1]))
    sock.send(bytes(str(sendkey),"utf-8"))
    key = pow(int(data[2]),int(secret),int(data[1]))
    return key
key = DH()
print("Key:",key)
while True:
    try:
        print("Receaving")
        data = sock.recv(1024)
        data=data.decode("utf-8")
        print(data)
    except Exception as e:
        print("A Recv error occured:\n",e)
    print(pow(int(data[0]),int(data[1])))
    try:
        toSend=input("Send: ")
        socket.send(bytes(toSend,"utf-8"))
    except Exception as f:
        print("A Send error occured:\n",f)
