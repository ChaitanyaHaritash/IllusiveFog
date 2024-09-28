from support import database
import configs
#Standard class name for each module when invoking
class IllusiveFogModule:
    def __init__(self,params=[]):
        self.params= params

        self.info={
            'Name'       : 'Recon Toolkit',
            'Description': 'Module Aims to perform different types of recon on compromised hosts.',
            'Author'     : 'Internal Dev Team',
            'Escalated'  :  False
        }

        self.options={
            'Operation': self.params[1],
            'Victim': self.params[0]
        }

        self.modulehelp = """
        Recon ToolKIT
        ===========
        Description : Module Aims to perform different types of recon on compromised hosts.
        URLS        : NA
        
        Options :
            1; UpdatesCheck - Check for updates installed.
                Usage - VerboseRecon UpdatesCheck
            2; MitigationsCheck - Check Mitigations installed in compromised host.
                Usage - VerboseRecon MitigationsCheck
            3; SystemInfo - Fetch Local system information about compromised host.
                Usage - VerboseRecon SystemInfo
            4; NetworkInfo - Fetch Local Network Info of compromised host.
                Usage - VerboseRecon NetworkInfo

        """


    #Privilege escalation Checker on known Nday.
    def UpdatesChecker(self):
        self.Escalate = "0xB11"
        if database.Victim().FetchVictimPrivLvl(self.victim) == "0":
            print "[-] Operation cannot be initiated since Victim is privileged enough."
            return False
        else:
            return self.Escalate

    #Available/Installed Mitigation Checker.
    def MitigationsChecker(self):
        self.mitigation = "0xB22"
        self.SupportedWinVer=["10","8","8.1"]
        if database.Victim().FetchVictimPrivLvl(self.victim) != "1":
            print "[-] Operation cannot be initiated since Victim is Not privileged enough."
            return False
        #elif self.SupportedWinVer not in database.Victim().FetchVictimOS(self.victim):
        #    print "[-] Plugin does not support : ",database.Victim().FetchVictimOS(self.victim)
        #    print "Only Windows 10, 8.1, 8 are support because feature of checking mitigations availability in selected versions."
        #    return False
        else:
            return self.mitigation

    #System Info Grabber of owned victim.
    def SystemInfoChecker(self):
        self.systeminfo = "0xB33"
        return self.systeminfo

    #Network Info Grabber of owned victim is in.
    def NetworkInfoChecker(self):
        self.NetworkInfo="0xB44"
        return self.NetworkInfo

#Main function which will be called, Must return
    def run(self):

        #saving options
        self.operation=self.options['Operation']
        self.victim = self.options['Victim']
        self.pluginsList = self.params[2]
        self.pluginsList = self.pluginsList.split(",")

        #split plugins according to job/command type
        self.NetworkSystem = self.pluginsList[0]
        self.Mitiesc=self.pluginsList[1]

        #print info about module
        print ""
        print "Module Info:"
        print "-----------"
        print "Name :"+self.info['Name'] 
        print "Description :"+self.info['Description']
        print "Author :"+self.info['Author']
        print "[info] For more info about module usage, use option 'help'. example: ETW help"
        print "\n"
        
        #split command in list
        self.initOperation=self.operation.split()
        #Show/Print help of Module
        if self.initOperation[0] == "help":
            #print self.pluginsList
            print self.modulehelp
            return False

        elif self.initOperation[0] == "UpdatesCheck":
            return [self.UpdatesChecker(),self.Mitiesc]
        
        elif self.initOperation[0] == "MitigationsCheck":
            return [self.MitigationsChecker(),self.Mitiesc]
        
        elif self.initOperation[0] == "SystemInfo":
            return [self.SystemInfoChecker(), self.NetworkSystem]

        elif self.initOperation[0] == "NetworkInfo":
            return [self.NetworkInfoChecker(),self.NetworkSystem]

        else:
            print "[ERROR] Incorrect Option"
            return False
