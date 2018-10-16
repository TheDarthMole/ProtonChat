import logging # https://docs.python.org/2.6/library/logging.html
def LogFile(data):
    data="".join(data)
    print(data)

    with open("Server.log","a") as file:
        file.write(data)
        file.close()
    
    print("Logged:",str(data))
    

#LogFile(b)


