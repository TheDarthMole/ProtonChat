from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from Crypto.Random import get_random_bytes
import hashlib


# AES supports multiple key sizes: 16 (AES128), 24 (AES192), or 32 (AES256).
key_bytes = 32
#key = b"\x98\x0b@\x92\xca\xfd%2\xc8'\xd99\xe3\n\x9f\xa7`\xe4{\xc1\x94\x05kn\x99\x11K\x9c\xc5\xa3\xb7\xe0" #get_random_bytes(key_bytes)
#print(key)
message = "This is a very long string that needs to be encrypted using AES-256"

iv =b'472397339731651527032246784262583994397535314940562482045920681491163415633042556334876037139321532739645262604595357120190547764249341332594033861505168261867106424915265321591594\
312295010061274782828437796985286854811915707' #get_random_bytes(16) / This is going to be the DiffieHellman
iv = (hex( int(iv) )[2:18]).encode("utf-8") # takes the first 16 hex values of iv
print()
print(iv)
iv_int = int( (iv).hex() , 16) # Convert the IV to a Python integer.

print(iv_int)
print(iv)
password = "This is a shit password"
salt_bytes = 8
salt = b'\xdfU\xc1\xdf\xf9\xb30\x96' # PreDefined

key = hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"), salt, 100000)
print("KeyLength",len(key))
print("Key:",key)

# Takes as input a 32-byte key and an arbitrary-length plaintext and returns a
# pair (iv, ciphtertext). "iv" stands for initialization vector.


def encrypt(key, iv, plaintext):
    assert len(key) == key_bytes
#    iv = Random.new().read(AES.block_size) # Choose a random, 16-byte IV.
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int) # Create a new Counter object with IV = iv_int.
    aes = AES.new(key, AES.MODE_CTR, counter=ctr) # Create AES-CTR cipher
    ciphertext = aes.encrypt(plaintext) # Encrypt and return IV and ciphertext.
    return (iv, ciphertext)

# Takes as input a 32-byte key, a 16-byte IV, and a ciphertext, and outputs the
# corresponding plaintext.
def decrypt(key, iv, ciphertext):
    assert len(key) == key_bytes
    # Initialize counter for decryption. iv should be the same as the output of
    # encrypt().

    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr) # Create AES-CTR cipher.
    plaintext = aes.decrypt(ciphertext) # Decrypt and return the plaintext.
    return plaintext

iv, ciphertext = encrypt(key, iv, bytes(message,"utf-8"))
print("IV:",iv,"\nCipherText:",ciphertext)
print(decrypt(key, iv, ciphertext).decode("utf-8"))















"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
data = b'This is a string'
key = get_random_bytes(16)
#cipher = AES.new(key, AES.MODE_EAX)
#ciphertext, tag = cipher.encrypt_and_digest(data)
#print(ciphertext)
def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CFB)
    ciphertext= cipher.encrypt_and_digest(data)
    print(ciphertext)
    return ciphertext

#print((encrypt(b'This is something to encrypt', key)))
encrypt(data, key)
"""
