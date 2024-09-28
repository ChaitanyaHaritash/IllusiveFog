#Shell Command Signatures

import re

#Common LolBins
signatureslolbas = {
     #BinName      Possible Detections                    MitreID
     'squirrel':['Update.exe spawned an unknown process','T1218'],
     'devtoolslauncher':['DeveloperToolsSvc.exe spawned an unknown process','T1218'],
     'update':['Update.exe spawned an unknown process','T1218'],
     'cl_mutexverifiers.ps1':['Monitor script processes, such as cscript, and command-line parameters for scripts like cl_mutexverifiers.ps1 that may be used to proxy execution of malicious files.','T1216'],
     'dxcap':['No Public Detections. Be Careful!','T1218'],
     'comsvcs':['MiniDump being used in library','T1003'],
     'wab':['WAB.exe should normally never be used','T1218'],
     'microsoft.workflow.compiler':['Microsoft.Workflow.Compiler.exe would not normally be run on workstations.','T1127'],
     'te':['No Public Detections. Be Careful!','T1218'],
     'mmc':['No Public Detections. Be Careful!','T1218'],
     'dnx':['No Public Detections. Be Careful!','T1218'],
     'at':['Scheduled task is created','T1053'],
     'extexport':['Extexport.exe loads dll and is execute from other folder the original path','T1218'],
     'cmstp':['Execution of cmstp.exe should not be normal unless VPN is in use','T1191'],
     'tttracer':['Parent child relationship. Tttracer parent for executed command','T1218'],
     'shell32':['No Public Detections. Be Careful!','T1085'],
     'pcwrun':['No Public Detections. Be Careful!','T1218'],
     'runscripthelper':['Event 4014 - Powershell logging','T1218'],
     'mavinject':['mavinject.exe should not run unless APP-v is in use on the workstation','T1218'],
     'advpack':['No Public Detections. Be Careful!','T1085'],
     'schtasks':['Services that gets created','T1053'],
     'ieexec':['No Public Detections. Be Careful!','T1105'],
     'installutil':['No Public Detections. Be Careful!','T1118'],
     'pubprn':['Monitor script processes, such as cscript, and command-line parameters for scripts like PubPrn.vbs that may be used to proxy execution of malicious files.','T1216'],
     'ie4uinit':['ie4uinit.exe loading a inf file from outside %windir%','T1218'],
     'infdefaultinstall':['No Public Detections. Be Careful!','T1218'],
     'rpcping':['No Public Detections. Be Careful!','T1003'],
     'vbc':['No Public Signatures. Be Careful!','T1127'],
     'pester.bat':['Might be monitored in Alternate Data Streames(ADS).','T1216'],
     'wmic':['Wmic getting scripts from remote system','T1096'],
     'ilasm':['No Public Signatures. Be Careful!','T1127'],
     'shdocvw':['No Public Detections. Be Careful!','T1085'],
     'regsvcs':['No Public Detections. Be Careful!','T1121'],
     'esentutl':['No Public Detections. Be Careful!','T1105'],
     'presentationhost':['No Public Detections. Be Careful!','T1218'],
     'msdeploy':['No Public Detections. Be Careful!','T1218'],
     'mshta':['mshta.exe executing raw or obfuscated script within the command-line','T1170'],
     'msconfig':['mscfgtlc.xml changes in system32 folder','T1218'],
     'desktopimgdownldr':['desktopimgdownldr.exe that creates non-image file','T1105'],
     'cscript':['Cscript.exe executing files from alternate data streams','T1096'],
     'certutil':['Certutil.exe creating new files on disk','T1105'],
     'gfxdownloadwrapper':['Usually GfxDownloadWrapper downloads a JSON file from https://gameplayapi.intel.com.','T1105'],
     'wscript':['Wscript.exe executing code from alternate data streams','T1096'],
     'ieadvpack':['No Public Detections. Be Careful!','T1085'],
     'syssetup':['No Public Detections. Be Careful!','T1085'],
     'regedit':['regedit.exe reading and writing to alternate data stream','T1096'],
     'dotnet':['dotnet.exe spawned an unknown process','T1218'],
     'cmd':['cmd.exe executing files from alternate data streams.','T1170'],
     'csc':['Csc.exe should normally not run a system unless it is used for development.','T1127'],
     'bginfo':['No Public Detections. Be Careful!','T1218'],
     'wsl':['Child process from wsl.exe','T1202'],
     'regasm':['regasm.exe executing dll file','T1121'],
     'netsh':['Netsh initiating a network connection','T1128'],
     'regini':['regini.exe reading from ADS','T1096'],
     'zipfldr':['No Public Detections. Be Careful!','T1085'],
     'pcalua':['No Public Detections. Be Careful!','T1218'],
     'winword':['No Public Detections. Be Careful!','T1105'],
     'vsjitdebugger':['No Public Detections. Be Careful!','T1218'],
     'print':['Print.exe getting files from internet','T1096'],
     'setupapi':['No Public Detections. Be Careful!','T1085'],
     'msiexec':['msiexec.exe getting files from Internet','T1218'],
     'sc':['Services that gets created','T1096'],
     'eventvwr':['eventvwr.exe launching child process other than mmc.exe','T1088'],
     'cmdkey':['Usage of this command could be an IOC','T1078'],
     'slmgr':['Monitor script processes, such as cscript, and command-line parameters for scripts like slmgr.vbs that may be used to proxy execution of malicious files.','T1216'],
     'odbcconf':['No Public Detections. Be Careful!','T1218'],
     'msxsl':['No Public Detections. Be Careful!','T1218'],
     'excel':['No Public Detections. Be Careful!','T1105'],
     'wsreset':['wsreset.exe launching child process other than mmc.exe','T1088'],
     'expand':['No Public Detections. Be Careful!','T1105'],
     'cdb':['No Public Detections. Be Careful!','T1218'],
     'rasautou':['rasautou.exe command line containing -d and -p','T1218'],
     'sqltoolsps':['No Public Detections. Be Careful!','T1218'],
     'extrac32':['No Public Detections. Be Careful!','T1096'],
     'replace':['Replace.exe getting files from remote server','T1105'],
     'hh':['hh.exe should normally not be in use on a normal workstation','T1105'],
     'gpscript':['Scripts added in local group policy','T1216'],
     'findstr':['finstr.exe should normally not be invoked on a client system','T1096'],
     'regsvr32':['regsvr32.exe getting files from Internet','T1117'],
     'diskshadow':['Child process from diskshadow.exe','T1218'],
     'runonce':['HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\YOURKEY','T1218'],
     'dnscmd':['Dnscmd.exe loading dll from UNC path','T1035'],
     'sqldumper':['No Public Detections. Be Careful!','T1003'],
     'bash':['Child process from bash.exe','T1218'],
     'mshtml':['No Public Detections. Be Careful!','T1085'],
     'psr':['psr.exe spawned','T1113'],
     'csi':['No Public Detections. Be Careful!','T1218'],
     'mftrace':['No Public Detections. Be Careful!','T1218'],
     'msdt':['No Public Detections. Be Careful!','T1218'],
     'url':['No Public Detections. Be Careful!','T1085'],
     'explorer':['Multiple instances of explorer.exe or explorer.exe using the /root command line can help to detect this.','T1218'],
     'winrm':['Monitor script processes, such as cscript, and command-line parameters for scripts like winrm.vbs that may be used to proxy execution of malicious files.','T1216'],
     'atbroker':['Changes to HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\Configuration','T1218'],
     'rundll32':['No Public Detections. Be Careful!','T1085'],
     'bitsadmin':['Child process from bitsadmin.exe','T1096'],
     'syncappvpublishingserver':['SyncAppvPublishingServer.exe should never be in use unless App-V is deployed','T1218'],
     'msbuild':['Msbuild.exe should not normally be executed on workstations','T1127'],
     'verclsid':['No Public Detections. Be Careful!','T1218'],
     'appvlp':['No Public Detections. Be Careful!','T1218'],
     'pcwutl':['No Public Detections. Be Careful!','T1085'],
     'xwizard':['No Public Detections. Be Careful!','T1218'],
     'forfiles':['No Public Detections. Be Careful!','T1218'],
     'reg':['reg.exe writing to an ADS','T1096'],
     'powerpnt':['No Public Signatures. Be Careful!','T1105'],
     'register-cimprovider':['No Public Detections. Be Careful!','T1218'],
     'manage-bde':['Manage-bde.wsf should normally not be invoked by a user','T1216'],
     'cl_invocation.ps1':['Monitor script processes, such as cscript, and command-line parameters for scripts like cl_invocation.ps1 that may be used to proxy execution of malicious files.','T1216'],
     'control':['Control.exe executing files from alternate data streams.','T1196'],
     'rcsi':['No Public Detections. Be Careful!','T1218'],
     'jsc':['Jsc.exe should normally not run a system unless it is used for development.','T1127'],
     'dfsvc':['No Public Detections. Be Careful!','T1127'],
     'ieaframe':['No Public Detections. Be Careful!','T1085'],
     'syncappvpublishingserver':['Monitor script processes, such as cscript, and command-line parameters for scripts like syncappvpublishingserver.vbs that may be used to proxy execution of malicious files.','T1216'],
     'ntdsutil':['ntdsutil.exe with command line including "ifm"','T1003'],
     'tracker':['No Public Detections. Be Careful!','T1218'],
     'ftp':['cmd /c as child process of ftp.exe','T1218'],
     'sqlps':['No Public Detections. Be Careful!','T1218'],
     'makecab':['Makecab getting files from Internet','T1096'],
     'scriptrunner':['Scriptrunner.exe should not be in use unless App-v is deployed','T1218'],
     'powershell':['Powershell Execution.','T1059']
}

def shellcmdsignaturedetector(shellcommand):
    signature=[]
    def checker(shellcommand):
        d = shellcommand.split(" ")
        try:
            for i in signatureslolbas.keys():
                if re.findall("(?i)("+i+")",shellcommand):
                    signature.append(signatureslolbas[i])
        except KeyError:
            pass
            #if i in shellcommand.split(" "):
            #    signature.append(signatureslolbas[i])
    
    checker(shellcommand)

    if not signature:
        return [0]
    else:
        return [signature,1]
