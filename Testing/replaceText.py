import time
from random import randint
def random():
    return randint(0,100)
"""
for i in range(10):
    print("\r"+"Message"+str(random()) + " " + str(i), end = "")
    time.sleep(1)
    if i == 9:
        print()
"""

"""
print("\r"+"Enter a string: ", end="")
time.sleep(1)
print("\r" + "This is receaved text")
print("\r"+"Enter a string2:", end="")
time.sleep(1)
"""


input1 = input("\rEnter the string: ")
print("\rThis is receaved text")
