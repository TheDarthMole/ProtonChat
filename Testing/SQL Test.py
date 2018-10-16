import sqlite3
import os
from random import randint
databasename=("TestClients.db")


def Commanddb(code):
    with sqlite3.connect(databasename) as conn:
        db=conn.cursor()
        db.execute(code)

def CreateTable():
    #try:
    Commanddb(''' CREATE TABLE clients (ip text, port integer, nickname text, code integer, PRIMARY KEY (nickname))''')
    #except:
        #print("Table already created")
    print("Done")

def printdb():
    with sqlite3.connect(databasename) as conn:
        db = conn.cursor()
        for row in db.execute('SELECT * FROM clients ORDER BY nickname'):
            print (row)

def deltable(file):
    os.remove(file)

def amenddb():

    printdb() # Print database
    KeyField = input("Enter the name user to amend: ")
    Field = input("Enter the field to amend: ")
    NewValue = input("Enter the new value: ")
    try:
        sql = "UPDATE clients SET {} = ? WHERE nickname = ?".format(Field)
        Commanddb(sql,(NewValue, KeyField))
        print("\nRecord Updated")
    except:
        print("Database not updated - Incorrect entry")
    printdb()

def AppendDatabase(ip, port, nickname, code, t=""):
    t=(ip, port, nickname, code)
    c.execute("INSERT INTO clients VALUES (?,?,?,?)", t)
    


def CreateOrders(): # Not part of coursework, POC
    sql="""
    CREATE TABLE Orders
    (OrderID interger,
    CustomerID integer,
    ProductID integer,
    Date date,
    Quantity integer,
    PRIMARY KEY (OrderID)
    FOREIGN KEY (ProductID) REFERENCES Products(ProductID)
    FOREIGN KEY (CustomerID) REFERENCES Customer(CustomerID) )
    """
    Commanddb(sql)

def CreateProduct():
    sql="""CREATE TABLE Product
    (ProductId INTERGER,
    Description text,
    Price real,
    PRIMARY KEY (ProductID))
    """
    Commanddb(sql)

def CreateCustomer():
    sql="""CREATE TABLE Customer
    (CustomerID interger,
    ProductID interger,
    Date text,
    Qty interger,
    FOREIGN KEY (ProductID) REFERENCES Product(ProductID) 
    FOREIGN KEY (CustomerID) REFERENCES Customer(CustomerID) )
    """
    Commanddb(sql)

def SearchCustomers():
    CustomerID=input("Enter the customer's ID: ")
    sql="""
    SELECT Customer.CustomerID, Product.ProductID, Product.Price, 1
    """



#deltable("")
CreateTable() # Clients one
CreateOrders()
CreateProduct()
CreateCustomer()



#printdb()
#amenddb()

