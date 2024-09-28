import aes
def pkcs1_unpad(text):
    if len(text) > 0 and text[0] == '\x02':
        # Find end of padding marked by nul
        pos = text.find('\x00')
        if pos > 0:
            return text[pos+1:]
    return None

def main():
    iv = "93e41c6e20911b9b36bc7ce94edc677e"
    data = "1b0539088e188b1a5071b1d45ca06e5b0a126803b0cec8f8786daa63418be09b6b9a92512a5e3393cfb51cbe8fcee3e5628ce38b91bcf4df52a37b2ec74e693772810e9f68411d4686498f6801d77d303e0481df4e84af2ee51bb67da02b35f8500c50f0411c167911161467929d1b0a624fe4f5bedf54c4619bbfa83ecea389cb4b866126ee012083a2f783561731c46a84bf112815257b0808080808080808"
    password = '20b5b0456a078602'
#Test CBC
    obj = aes.AESCBC()
    #enc= obj.encrypt(data,password)
    #print enc.decode("base64")
    #enc= enc.decode("base64")
    #print enc
    #enc= enc.split(" <hr> ")
    #data = data.decode("base64")
    #enc = data.split(" <hr> ")
    #iv = enc.split(" <hr> ")[0]
    #cipher = enc[1]
    dec = obj.decrypt(data,iv,password)
    print dec

    

#Test CFB
'''
    print "CFB"
    obj = aes.AESCFB()
    enc = obj.encrypt(data,password)
    print "IV - Cipher : "+enc
    enc=enc.decode("base64").split(" ~T~ ")
    print "hex encoded key: ",password.encode("hex")
    dec = obj.decrypt(str(enc[1]),str(enc[0]),password)
    print "Decrypted: ",dec
'''

main()
