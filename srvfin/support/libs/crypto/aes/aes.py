#!/usr/bin/python
'''
https://github.com/artikrh/HackTheBox/blob/master/Fortune/files/crypto.py

AES-CBC is currently in use cos of limited learning and implementation on
AES-CFB available. But i dont support usage of CBC since its easily available
and IV can leave enough hints to recover some corpus from communication and 
encrypted text. Whereas CFB is very hard to reteive anything from encrypted text
also IV leaves very limited hints in corpus.

'''
import base64,re
import hashlib
import sys

from Crypto import Random
from Crypto.Cipher import AES
from pkcs7 import PKCS7Encoder

import binascii, os

#-------------------
# AES with CFB mode
#-------------------
class AESCFB:
    def __init__(self):
        self.padding_string = b'}'
    
    def encrypt(self,plaintext, key):
        """
        Encrypt the plaintext with AES method.

        Parameters:
            plaintext -- String to be encrypted.
            key       -- Key for encryption.
        """

        iv = (binascii.b2a_hex(os.urandom(16))).decode("hex")
        cipher = AES.new(self.pad(key), AES.MODE_CFB, iv)
        # If user has entered non ascii password (Python2)
        # we have to encode it first
        if hasattr(str, 'decode'):
            plaintext = plaintext.encode('utf-8')
        encrypted = base64.b64encode(iv.encode("hex") +" ~T~ "+ (cipher.encrypt(plaintext)).encode("hex"))
        
        return encrypted


    def decrypt(self,ciphertext,iv, key):
        """
        Decrypt the AES encrypted string.

        Parameters:
            ciphertext -- Encrypted string with AES method.
            key        -- key to decrypt the encrypted string.
            iv         -- IV.
        """

        ciphertext = (ciphertext).decode("hex")
        iv = iv.decode("hex")
        cipher = AES.new(self.pad(key), AES.MODE_CFB, iv)
        decrypted = cipher.decrypt(ciphertext)

        return decrypted

    def pad(self,key):
        """Add padding to the key."""
        str_len = len(key)

        # Key must be maximum 32 bytes long, so take first 32 bytes
        if str_len > 32:
            return key[:32]

        # If key size id 16, 24 or 32 bytes then padding not require
        if str_len == 16 or str_len == 24 or str_len == 32:
            return key

        # Convert bytes to string (python3)
        if not hasattr(str, 'decode'):
            self.padding_string = padding_string.decode()

        # Add padding to make key 32 bytes long
        return key + ((32 - str_len % 32) * self.padding_string)




#---------------------
# AES with CBC mode
#---------------------

class AESCBC:
    
    def __init__(self):
        self.coder = PKCS7Encoder()
#        self.BS = 16
#        self.pad = lambda s: s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS)
        #self.unpad = lambda s : s[0:-ord(s[-1])]
    
    def encrypt(self,plaintext, key):

        iv = (binascii.b2a_hex(os.urandom(16))).decode("hex")
        key=bytes(key)        
        iv=bytes(iv)        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext=bytes(plaintext)
        pad_text = self.coder.encode(plaintext)
        
        # If user has entered non ascii password (Python2)
        # # we have to encode it first
        #if hasattr(str, 'decode'):
        #    plaintext = plaintext.encode('utf-8')
      
        #encrypted = base64.b64encode(iv.encode('hex') +" <hr> "+ cipher.encrypt(plaintext).encode('hex'))
        encrypted = base64.b64encode(iv.encode('hex') +" <hr> "+ cipher.encrypt(pad_text).encode('hex'))
        return encrypted
    
    def decrypt(self,ciphertext,iv, key):
        #ciphertext = ciphertext.decode("hex")
        ciphertext = (re.sub(r'[^\w]', '', ciphertext)).decode("hex")
        iv=iv.decode("hex")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = self.coder.decode(cipher.decrypt(ciphertext))
#	decrypted = cipher.decrypt(ciphertext)
        return decrypted
    
    def decryptHexDecoded(self,ciphertext,iv, key):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = self.coder.decode(cipher.decrypt(ciphertext))
#	decrypted = cipher.decrypt(ciphertext)
        return decrypted
