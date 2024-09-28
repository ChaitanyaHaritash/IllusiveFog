import configparser
import os
'''Fetching Configuration from config file'''
class configuration:
    config = configparser.ConfigParser()
    config.read('config.ini')
    
    c2 = config['C2']
    flask = config['FLASK']
    plugin = config['Plugins']
    VT = config['VirusTotal']
    pellets=config['Pellets']
    
    if os.name == "nt":
        localpath= os.getcwd()
        pluginPath=localpath+"\\"+c2['PLUGINS_PATH']+"\\"
        dbPath = localpath+"\\support\\"
        pelletsPath = pluginPath+c2['PELLETS_PATH']+"\\"
    else:
        localpath = os.getcwd()
        pluginPath=localpath+"/"+c2['PLUGINS_PATH']+"/"
        dbPath = localpath+"/support/"
        pelletsPath = pluginPath+c2['PELLETS_PATH']+"/"