#!/usr/bin/python
'''
https://github.com/artikrh/HackTheBox/blob/master/Fortune/files/crypto.py
'''
import base64
import hashlib
import sys

from Crypto import Random
from Crypto.Cipher import AES
import binascii, os
padding_string = b'}'


def encrypt(plaintext, key):
    """
    Encrypt the plaintext with AES method.

    Parameters:
        plaintext -- String to be encrypted.
        key       -- Key for encryption.
    """

    iv = (binascii.b2a_hex(os.urandom(16))).decode("hex")
    cipher = AES.new(pad(key), AES.MODE_CFB, iv)
    # If user has entered non ascii password (Python2)
    # we have to encode it first
    if hasattr(str, 'decode'):
        plaintext = plaintext.encode('utf-8')
    encrypted = iv.encode("hex") +"#"+ (cipher.encrypt(plaintext)).encode("hex")
    
    return encrypted


def decrypt(ciphertext,iv, key):
    """
    Decrypt the AES encrypted string.

    Parameters:
        ciphertext -- Encrypted string with AES method.
        key        -- key to decrypt the encrypted string.
        iv         -- IV.
    """

    global padding_string

    ciphertext = (ciphertext).decode("hex")
    iv = iv.decode("hex")
    cipher = AES.new(pad(key), AES.MODE_CFB, iv)
    decrypted = cipher.decrypt(ciphertext)

    return decrypted

def pad(key):
    """Add padding to the key."""

    global padding_string
    str_len = len(key)

    # Key must be maximum 32 bytes long, so take first 32 bytes
    if str_len > 32:
        return key[:32]

    # If key size id 16, 24 or 32 bytes then padding not require
    if str_len == 16 or str_len == 24 or str_len == 32:
        return key

    # Convert bytes to string (python3)
    if not hasattr(str, 'decode'):
        padding_string = padding_string.decode()

    # Add padding to make key 32 bytes long
    return key + ((32 - str_len % 32) * padding_string)


def pqencryptpassword(password, user):
    """
    pqencryptpassword -- to encrypt a password
    This is intended to be used by client applications that wish to send
    commands like ALTER USER joe PASSWORD 'pwd'.  The password need not
    be sent in cleartext if it is encrypted on the client side.  This is
    good because it ensures the cleartext password won't end up in logs,
    pg_stat displays, etc. We export the function so that clients won't
    be dependent on low-level details like whether the enceyption is MD5
    or something else.

    Arguments are the cleartext password, and the SQL name of the user it
    is for.

    Return value is "md5" followed by a 32-hex-digit MD5 checksum..

    Args:
      password:
      user:

    Returns:

    """

    m = hashlib.md5()

    # Place salt at the end because it may be known by users trying to crack
    # the MD5 output.
    # Handling of non-ascii password (Python2)
    if hasattr(str, 'decode'):
        password = password.encode('utf-8')
        user = user.encode('utf-8')
    else:
        password = password.encode()
        user = user.encode()

    m.update(password)
    m.update(user)

    return "md5" + m.hexdigest()

#ciphertext = "utUU0jkamCZDmqFLOrAuPjFxL0zp8zWzISe5MF0GY/l8Silrmu3caqrtjaVjLQlvFFEgESGz"
#key = sys.argv[1]
#print decrypt(ciphertext,key)