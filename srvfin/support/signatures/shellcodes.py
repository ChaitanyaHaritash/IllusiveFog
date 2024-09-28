#Shellcode Signatures DataBase.

#Metasploit shellcodes Signatures
metasploit = {
                'Generic_Metasploit_x86' : [r'\xfc\xe8\x82\x00\x00\x00\x60', 'Generic.Metasploit.x86'],
                'Metasploit_EncoderX86_Shikate_Ga_Nai' : [r'\xd9\x74\x24\xf4','MSF_EncoderX86.Shikate_GA_NAI'],
                'Generic_Metasploit_x64' : [r'\xfc\x48\x83\xe4\xf0\xe8', 'Generic.Metasploit.x64'],
                'Metasploit_x86_blind'   : [r'\xfc\xe8\x89\x00\x00\x00\x60','Metasploit.x86_blind']
}

#CobaltStrike Signatures
cobaltstrike = {
                '':''
}


#Signature Checking
def shellcodesignaturedetector(shellcode):
    signatures=[]
    
    def checker(shellcode):
        if metasploit['Generic_Metasploit_x86'][0] in shellcode:
            signatures.append(metasploit['Generic_Metasploit_x86'][1])
        
        if metasploit['Metasploit_EncoderX86_Shikate_Ga_Nai'][0] in shellcode:
            signatures.append(metasploit['Metasploit_EncoderX86_Shikate_Ga_Nai'][1])
        
        if metasploit['Generic_Metasploit_x64'][0] in shellcode:
            signatures.append(metasploit['Generic_Metasploit_x64'][1])
        
        if metasploit['Metasploit_x86_blind'][0] in shellcode:
            signatures.append(metasploit['Metasploit_x86_blind'][1])
    
    checker(shellcode)
    
    if not signatures:
        return [0]
    else:
        return [', '.join(signatures),1]    
