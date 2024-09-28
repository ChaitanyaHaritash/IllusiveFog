import os
import shutil
import importlib

#__init__ remover from directory structure list
def initRemover(P):
    if P.find("__init__") == 1:
        P.remove(P)
    return P

def pycRemover(path):
    for parent, dirnames, filenames in os.walk(path):
        for fn in filenames:
            if fn.lower().endswith('.pyc'):
                os.remove(os.path.join(parent, fn))

# Loading modules on Boot
def moduleCheckonBoot():
    modulesPath = "modules/"
    pycRemover(modulesPath)
    try:
        Path=[x[0] for x in os.walk(modulesPath)]
        
        for u in Path:
            initRemover(u)
        Path.pop(0)
        
        try:
            for d in Path:
                for parent, dirnames, filenames in os.walk(d):
                    filenames.remove("__init__.py")
                    for fn in filenames:
                        r = "modules."+parent.replace(modulesPath,"")
                        runner= r+"."+fn.replace(".py","")
                        importlib.import_module(runner)
        except ValueError:
            pass

    except ValueError:
        pass

    except Exception as e:
        print e
        pass

def arbitrarilyImportModule(module_name):
    try:
        importer=importlib.import_module("modules."+module_name)
        return importer
    except Exception as e:
        print e
        pass