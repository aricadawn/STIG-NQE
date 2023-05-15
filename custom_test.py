import requests
import json
from STIG_NQE import TOKEN 
from STIG_NQE import custom_url

def custom(command):
    API_URL = custom_url
    PATCH_URL = API_URL + '/stig'

    r = requests.get(API_URL, auth=TOKEN)
    response = r.text
    js = json.loads(response)
    names = []
    payload = {'name': 'stig', 'deviceConnTypes': ['cisco_ios_ssh', 'cisco_ios_xe_ssh', 'cisco_nxos_ssh', 'cisco_asa_ssh'], 'commands': [command], 'disabled': False}
    for item in js:
        names.append(item['name'])
    if 'stig' not in names:
        r = requests.post(API_URL, json=payload, auth=TOKEN)
    for item in js:
        if item['name'] == 'stig':
            if command not in item['commands']:
                item['commands'].append(command)
                r = requests.patch(PATCH_URL, json=item, auth=TOKEN)

