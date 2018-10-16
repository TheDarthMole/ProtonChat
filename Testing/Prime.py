from random import randint
import time

def is_prime(num, test_count):
    if num == 1:
        return False
    if test_count >= num:
        test_count = num - 1
    for x in range(test_count):
        val = randint(1, num - 1)
        if pow(val, num-1, num) != 1:
            return False
    return True

def generate_big_prime(n):
    found_prime = False
    while not found_prime:
        p = randint(2**(n-1), 2**n)
        if is_prime(p, 1000):
            return p

t1=time.clock()
number = 1536
print("Generating Prime")
randomnum = randint(4**336,4**350)
print("RandomNum",randomnum)
actual = generate_big_prime(randomnum)
print(actual)
print("Done in "+str(time.clock()-t1))
