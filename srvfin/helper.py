#Helpter Library

import random
import string
import os 
import json
import hashlib
import re
import base64

#application installation path
def CurrentPath():
	return os.getcwd() + "/"

#Generate Random Strings of fixed length
def randomString(stringLength=6):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

def RandomKeysGeneratorAES(length):
    letters_and_digits = "a"+"b"+"c"+"d"+"e"+"f"+"0"+"2"+"3"+"4"+"5"+"6"+"7"+"8"+"9"+"0"
    result_str = ''.join((random.choice(letters_and_digits) for i in range(length)))
    #result_str = "\\x"+'\\x'.join(result_str[i:i + 2] for i in range(0, len(result_str), 2)) 
    return b''+result_str

#Console Messages colors
#def print_red(skk): print("\033[91m {}\033[00m" .format(skk)) 
#def print_green(skk): print("\033[92m {}\033[00m" .format(skk)) 

#Function to write files
def writeFile(name,path,data):
	f = open(CurrentPath()+path+name,'w+')
	f.write(data)
	f.close()

#Function to write json files
def JsonWriteFile(name,path,data):
	with open(CurrentPath()+path+name, 'w') as f:
		loads = json.loads(data)
		json.dump(loads, f)

#Function to read files
def openFileRead(name,path):
	f = open(CurrentPath()+path+name,'r+')
	return f.read()

#This function returns the SHA-1 hash of the file passed into it
def hash_file(filename):
   # make a hash object
   h = hashlib.sha1()

   # open file for reading in binary mode
   with open(filename,'rb') as file:

       # loop till the end of the file
       chunk = 0
       while chunk != b'':
           # read only 1024 bytes at a time
           chunk = file.read(1024)
           h.update(chunk)

   # return the hex representation of digest
   return h.hexdigest()

#Get file Name from Literal Path String And verify
def GetFileName(path):
    return os.path.basename(path)


#base64 to hex encode plain text
def b64tohex_decode(p):
    p = (p.decode("base64")).decode("hex")
    return p

#base64 to hex
def hextob64_encode(p):
    p=(p.encode("hex")).encode("base64")
    return p 

#Base64 Correct padding
def B64DecodeWithPadding(data, altchars=b'+/'):
    data = re.sub(r'[^a-zA-Z0-9%s]+' % altchars, b'', data)  # normalize
    missing_padding = len(data) % 4
    if missing_padding:
        data += b'='* (4 - missing_padding)
    return base64.b64decode(data, altchars)