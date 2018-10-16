import sqlite3, os
databasename = "Clients1.db"

def CommandDB(code): # Semi-universal SQL command executor, however allows SQL injection when variable enterd
    with sqlite3.connect(databasename) as conn:
        db=conn.cursor()
        db.execute(code)
        data = db.fetchall()
        return data


def CreatClientsTable():
    try:
        CommandDB("CREATE TABLE clients (ip text, port integer, nickname text, code integer, PRIMARY KEY (nickname))")
        print("[+] Database Created")
    except sqlite3.OperationalError:
        print("[=] Database already created")
        
def SearchCode(Code):
    with sqlite3.connect(databasename) as conn:
        db=conn.cursor()
        db.execute("SELECT * FROM clients WHERE code = ?",(Code,))
        data = db.fetchall()
    return data
    

def PrintCustomerContents():
    data = CommandDB("SELECT * FROM clients")
    print("\n       IP           PORT     NickName    Code\n" +"-"*48)
    for row in data:
        print("{:^18}{:^10}{:^10}{:^10}".format(row[0],row[1],row[2],row[3]))

def AppendDatabase(ip, port, nickname, code):
    with sqlite3.connect(databasename) as conn:
        db=conn.cursor()
        db.execute("INSERT INTO clients VALUES (?,?,?,?)",(ip, port, nickname, code))
        conn.commit()

os.remove(databasename)
CreatClientsTable()
AppendDatabase("255.255.255.255","666","Nick",1337)
AppendDatabase("1.1.1.1","5588","James",1338)
AppendDatabase("2.2.2.2","45842","Alex",1339)
PrintCustomerContents()
SearchCode(1337)
