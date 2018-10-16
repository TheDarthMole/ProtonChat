# use Python 3 print function
# this allows this code to run on python 2.x and 3.x
from __future__ import print_function

# Variables Used
sharedPrime = 104618633796443892858069965748889693248027658415310230606953548714771997102999    # p
sharedBase = 663      # g

ServerSecret = 27266380874037097584116106428749529740507604     # a
ClientSecret = 38771176839568955352494746951777619189571125      # b

# Begin
print( "Publicly Shared Variables:")
print
print( "    Publicly Shared Prime: " , sharedPrime )
print( "    Publicly Shared Base:  " , sharedBase )

# Server Sends Client A = g^a mod p
#A = (sharedBase**ServerSecret) % sharedPrime
A = pow(sharedBase, ServerSecret, sharedPrime)
print( "\n  Server Sends Over Public Chanel: " , A )

# Client Sends Server B = g^b mod p
#B = (sharedBase ** ClientSecret) % sharedPrime
B = pow(sharedBase, ClientSecret, sharedPrime)
print( "  Client Sends Over Public Chanel: ", B )

print( "\n------------\n" )
print( "Privately Calculated Shared Secret:" )
# Server Computes Shared Secret: s = B^a mod p
#ServerSharedSecret = (B ** ServerSecret) % sharedPrime
ServerSharedSecret = pow(B, ServerSecret, sharedPrime)
print( "    Server Shared Secret: ", ServerSharedSecret )

# Client Computes Shared Secret: s = A^b mod p
#ClientSharedSecret = (A**ClientSecret) % sharedPrime
ClientSharedSecret = pow(A, ClientSecret, sharedPrime)
print( "    Client Shared Secret: ", ClientSharedSecret )
