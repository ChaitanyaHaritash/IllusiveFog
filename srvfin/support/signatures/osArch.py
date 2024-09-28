#OS Version Detections
'''
+------------------------------------------------------------------------------+
|                    |   PlatformID    |   Major version   |   Minor version   |
+------------------------------------------------------------------------------+
| Windows 95         |  Win32Windows   |         4         |          0        |
| Windows 98         |  Win32Windows   |         4         |         10        |
| Windows Me         |  Win32Windows   |         4         |         90        |
| Windows NT 4.0     |  Win32NT        |         4         |          0        |
| Windows 2000       |  Win32NT        |         5         |          0        |
| Windows XP         |  Win32NT        |         5         |          1        |
| Windows 2003       |  Win32NT        |         5         |          2        |
| Windows Vista      |  Win32NT        |         6         |          0        |
| Windows 2008       |  Win32NT        |         6         |          0        |
| Windows 7          |  Win32NT        |         6         |          1        |
| Windows 2008 R2    |  Win32NT        |         6         |          1        |
| Windows 8          |  Win32NT        |         6         |          2        |
| Windows 8.1        |  Win32NT        |         6         |          3        |
+------------------------------------------------------------------------------+
| Windows 10         |  Win32NT        |        10         |          0        |
+------------------------------------------------------------------------------+
'''

Versions = {
   
   #PlatformID 
   'Win32Windows' : [
                        #   os       MaV MiV  
                        ['Windows95','4','0'],
                        ['Windows98','4','10'],
                        ['WindowsMe','4','90']
                    ],
   #PlatformID
   'Win32NT' : [
                #   os       MaV MiV
                ['Windows NT 4.0','4','0'],
                ['Windows 2000','5','0'],
                ['Windows XP','5','1'],
                ['Windows 2003','5','2'],
                ['Windows Vista','6','0'],
                ['Windows 2008','6','0'],
                ['Windows 7','6','1'],
                ['Windows 2008 R2','6','1'],
                ['Windows 8','6','2'],
                ['Windows 8.1','6','3'],
                ['Windows 10','10','0']
   ]
}

def DetectOS(o):
    p = ""
    for i in Versions['Win32NT']:
        if o in i[0]:
            p = i
    return p
