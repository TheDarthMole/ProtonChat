publicPrime = 27
publicBase = 2
privateServer = 731
privateClient = 653

string="ABC"


def getChar(char):
    order = ord(char)
    return order

def ordify(string):
    ordString = ""
    ordChar = ""
    for i in range(len(string)):
        ordChar = getChar(string[i])
        if i+1 == int(len(string)):
            ordString = ordString+str(ordChar)
        else:
            ordString = ordString+str(ordChar) + " "
    return ordString




def encrypter(string, publicPrime, publicBase, privateServer, privateClient):
    encryptedString = ""
    orderString = ordify(string)
    print (orderString)
    orderString=orderString.split(" ")
    for i in range(len(orderString)):
#        print(orderString[i])
        if i+1 == len(orderString):
            encryptedString = encryptedString + str(pow(int(orderString[i]),privateClient, publicPrime))
        else:
            encryptedString = encryptedString + str(pow(int(orderString[i]),privateClient, publicPrime)) + " "
    return encryptedString

finalString = encrypter(string, publicPrime, publicBase, privateServer, privateClient)
print(finalString)


