class AESCipher(object):
    def __init__(self, key):
        self.key = self.hasher(key)
        # Hashes a value and uses it as the cipher

    def hasher(self, password):
        salt = b'\xdfU\xc1\xdf\xf9\xb30\x96'
        # This is the default salt i am using for client and server side
        # Theoretically this should be random for each user and stored in the database
        return (  hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"), salt, 1000000)  )
        # Returns the hashed password using PBKDF2 HMAC

    def encrypt(self, raw):
        b64 = base64.b64encode(raw.encode("utf-8")).decode("utf-8")
        # Base 64 encoding using "UTF-8" encoding
        raw = self.pad(b64)
        # Padded so that it is a multiple of 16 (Block cipher length)
        rawbytes = bytes(raw,"utf-8")
        iv = Random.new().read(AES.block_size)
        # Random IV to make the ciphertext random
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        # New cipher instance using the random IV and the encryption key
        return base64.b64encode(iv + cipher.encrypt(rawbytes))
        # Returns the data encrypted and in base4 format

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        # Splits up the IV and the data
        try:
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
        except ValueError:
            print("[!] ValueError Occured")
        # Try except because not all data going into the fucntion is decryptable
        Decrypted = cipher.decrypt(enc[AES.block_size:])
        unpadded = self.unpad(Decrypted).decode("utf-8")
        # Decrypts and unpads the data
        Decoded = base64.b64decode(unpadded).decode("utf-8")
        return Decoded
        # Returns the decrypted data as a plaintext string

    def pad(self,s): # Pads the string so that it complys with the AES 16 byte block size
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)
        # Pads the data to a size of multiple 16

    def unpad(self, s): # Turns the 16 byte complyant string to a normal string
        return s[:-ord(s[len(s)-1:])]
        # Removes the padding from a string
import hashlib
cipher = AESCipher("This is a key")
# print(cipher.hasher("This is a password"))
print(cipher.hasher("Nick").hex())
