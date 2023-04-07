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
TOKEN = apiVb.TOKEN_FNSAAS

# JSON formatted NQE 
nqe = '''
/**\n * @intent {}\n\n * @description {}\n\n * Version//Revision: V2R4\n * Vuln ID: {}\n * Severity: {}\n * Group Title: {}\n * Rule ID: {}\n * Rule_Version: {}\n */\n\n{}\n\n/* \nCheck Content: {}\n*/\n\n/* \nFix Text: {}\n*/\n\nstigData =\n  {{ os: OS.IOS_XE,\n    vulnId: "{}",\n    groupTitle: "{}",\n    ruleId: "{}",\n    severity: "{}",\n    ruleVersion: "{}",\n    legacyVulns: "[{}]"\n  }}; \n{}
'''

NQE_txt = 'queries.txt'
STIG_csv = 'Cisco IOS XE Router RTR V2R6.csv'
creat_dir = 'https://fwd.app/api/users/current/nqe/changes?action=addDir&path=/Arica/{}/'.format(STIG_csv.strip('.csv'))

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
               k, l = filters.dictionary(filters.pattern(j))
               sourceCode = nqe.format(g,h,a,b,c,d,e,k,j,i,a,c,d,b,e,f,l)
               payload = {'queryType': 'QUERY', 'sourceCode': sourceCode}
               r = requests.post(API_URL.format(STIG_csv.strip('.csv'), e), json=payload, auth=TOKEN)
               # file_out.write(json.dumps(payload))
               file_out.write(sourceCode)
               

if __name__ == '__main__':
   STIG_NQE(NQE_txt, STIG_csv)