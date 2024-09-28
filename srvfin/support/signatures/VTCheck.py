#Check If samples are submitted on VirusTotoal by hash search

import requests
import json,time
import helper as he

"""
scans
scan_id
sha1
resource
response_code
scan_date
permalink
verbose_msg
sha256
positives
total
md5
"""

def VTChecker(key,file):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    f = len(file)

    for i in file:
        for i in file:
            params = {'apikey': key, 'resource': he.hash_file(i)}
            response = requests.get(url, params=params)

            if response.status_code == 204:
                print "\n[!] Taking 60 seconds break.\nbac"
                time.sleep(60)
                response = requests.get(url, params=params)
                if dict(response.json())['response_code'] == 0:
                    print i," => Not Submitted."
                else:
                    print i," => Submitted."
    
            else:
                if dict(response.json())['response_code'] == 0:
                    print i," => Not Submitted."
                else:
                    print i," => Submitted."

            if f == 0:
                break
            else:
                f = f-1
                continue
        break
        
