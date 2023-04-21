import csv
import requests
import json
import sys
import filters

# import apiVb.py file where api url and token are stored locally
sys.path.insert(0, '/Users/aricabeckstead/')
import apiVb #type:ignore
# EXAMPLE:
# API_URL = "https://fwd.app/api/users/current/nqe/changes?action=addQuery&path=/{FOLDER}/{QUERY-NAME}"
# TOKEN = ('ACCESS-KEY', 'SECRET-KEY')

API_URL = apiVb.API_URL
TOKEN = apiVb.korg

# JSON formatted NQE 
nqe = '''
/**\n * @intent {}\n\n * @description {}\n\n * Version//Revision: V2R4\n * Vuln ID: {}\n * Severity: {}\n * Group Title: {}\n * Rule ID: {}\n * Rule_Version: {}\n */\n\n{}\n\n/* \nCheck Content: {}\n*/\n\n/* \nFix Text: {}\n*/\n\nstigData =\n  {{ os: OS.{},\n    vulnId: "{}",\n    groupTitle: "{}",\n    ruleId: "{}",\n    severity: "{}",\n    ruleVersion: "{}",\n    legacyVulns: "[{}]"\n  }}; \n{}
'''

STIG_csv = [
'Cisco ASA Firewall V1R3.csv',
'Cisco ASA NDM V1R3.csv',
'Cisco ASA VPN V1R1.csv',
'Cisco IOS Router NDM V2R4.csv',
'Cisco IOS Router RTR V2R3.csv',
'Cisco IOS Switch L2S V2R3.csv',
'Cisco IOS Switch NDM V2R4.csv',
'Cisco IOS Switch RTR V2R2.csv',
'Cisco IOS_XE Router RTR V2R6.csv',
'Cisco IOS_XE Switch RTR V2R2.csv',
'Cisco NXOS Switch L2S V1R1.csv',
'Cisco NXOS Switch NDM V2R3.csv',
'Cisco NXOS Switch RTR V2R1.csv'
]

def STIG_NQE(NQE_txt, STIG_csv):
   '''
   1. file_out stores queries in txt file - used for testing.
   2. file_in is an export of STIG in csv format.
   3. Iterates over file_in to retrieve relevant stig information and create NQE.
   4. Creates API POST to create NQE for each STIG.
   '''
   r = requests.post(creat_dir, auth = TOKEN) 
   with open(NQE_txt, 'w') as file_out:
      with open(STIG_csv, 'r') as file_in:
         reader = csv.DictReader(file_in)
         for row in reader:
               a = row['Vuln ID']
               b = row['Severity']
               c = row['Group Title']
               d = row['Rule ID']
               e = row['STIG ID']
               f = row['Legacy']
               g = row['Rule Title']
               h = row['Discussion']
               i = row['Fix Text']
               j = row['Check Content']
               k, l = filters.dictionary(filters.pattern(j,i)) 
               m = deviceOs
               sourceCode = nqe.format(g,h,a,b,c,d,e,k,j,i,m,a,c,d,b,e,f,l)
               payload = {'queryType': 'QUERY', 'sourceCode': sourceCode}
               r = requests.post(API_URL.format(STIG_csv.strip('.csv'), e), json=payload, auth=TOKEN)
               # file_out.write(json.dumps(payload))
               file_out.write(k)
               print(e)
                           
if __name__ == '__main__':
   NQE_txt = 'queries.txt'
   for stig in STIG_csv:
       deviceOs = stig.split()[1]
       creat_dir = 'https://fwd.app/api/users/current/nqe/changes?action=addDir&path=/Arica/{}/'.format(stig.strip('.csv'))
       STIG_NQE(NQE_txt, stig)