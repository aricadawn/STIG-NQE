import re

def pattern(check_content): 
    """
    Filters Check Content portion of STIG to collect configuration and create a list of pattern variables. 
    """
    mode = False
    lines = []
    for line in check_content.splitlines():
        if not mode:
            if line.startswith(('Review', 'Step', 'Verify', 'Cisco router')) or line.endswith(('below:', 'example below.')):
                mode = True
        elif line.startswith('If'):
            mode = False
        else:
            lines.append(line)

    filters = [r'Example', r'example', r'Note', r'NOTE', r'Step', r'proceed', r'below', r'Verify', r'Review', r'Altern', r'https://', r'IF', r'!', r'[1-3]\. ', r'[2]\. '
            #    r'\u2026$', r'^\u2026', r'\u2026',
               ]
    for word in filters:
        for item in lines:
            if re.findall(word, item):
                lines.remove(item)
            elif u'\u2026' in item:
                lines.remove(item)

    interfaceCnt = 1
    keyCnt = 1
    ipCnt = 1
    counter = False
    for index, item in enumerate(lines):
        if item.startswith(('interface', ' interface')):
            lines[index] = '''interface {}'''.format(interfaceCnt)
            interfaceCnt += 1
        elif 'key-string' in item:
            lines[index] = ''.join(item.rsplit(' ', 1)[0]) + ' {{key{}: string}}'.format(keyCnt)
            keyCnt += 1
        elif 'ip address' in item:
            lines[index] = ''' ip address {ip: ipv4Address}'''
            ipCnt += 1
        elif 'description' in item:
            lines[index] = ''' description {desc: string}'''
        elif 'hostname' in item:
            lines[index] = '''hostname {host: string}'''
          
        if not counter:
            if item.startswith(('interface', ' interface')):
                counter = True
        elif item == '':
            counter = False
        else:
            if item[0] != ' ' and 'interface' not in item and 'ip access-list' not in item:
                lines[index] = ' ' + item
    return lines

def dictionary(pattern):
    """
    1. Creates a dictionary of pattern variables by filtering through list created in pattern function.
    2. Returns pattern variables and formatted query as strings 
    """
    query = [
       'foreach device in network.devices',
       'where device.platform.os == stigData.os',
    ]
    intQuery = '''
interfaceViolation(device) = 
foreach interface in patternMatches(device.files.config, `interface {name:string}`)
let lines = (foreach child in interface.line.children select child)
'''
    select1 = '''
select {
  violation: isPresent(device.name),
  device: device.name,
  deviceModel: device.platform.model,
  mgmtIP: device.platform.managementIps,
  Severity: stigData.severity,
  Group_Title: stigData.groupTitle,
  Vuln_ID: stigData.vulnId,
  Rule_ID: stigData.ruleId,
  Rule_Version: stigData.ruleVersion
}'''
    select2 = '''
select {
  violation: isPresent(device.name),
  device: device.name,
  interface: (foreach int in intViolation select int.data.name),
  deviceModel: device.platform.model,
  mgmtIP: device.platform.managementIps,
  Severity: stigData.severity,
  Group_Title: stigData.groupTitle,
  Vuln_ID: stigData.vulnId,
  Rule_ID: stigData.ruleId,
  Rule_Version: stigData.ruleVersion
}'''

    custom = '''let outputs = device.outputs
foreach command in outputs.commands
where command.commandText == "{}"
let showOutput = parseConfigBlocks(device.platform.os, command.response)
let match = max(blockMatches_alpha1(showOutput, show))'''
    show = []
    showCount = 0
    for line in pattern:
        if showCount == 0 :
            if re.search(r'#show|# show', line):
                showCount += 1
                custom = custom.format(line.split('#')[1])
        elif line != '':
            show.append(line)

    dictionary = {}
    def setname(d, n):
        if n.startswith('interface'):
           d[n] = []
        else:
           d[n] = [n]

    for item in [z for z in pattern if len(z) > 0 ]:
        """
        1. Reformats items returned in pattern to match configuration syntax
        2. Creates dictionary of pattern variables 
        """
        tup = [(r' [nxyz]{2,}', ' '), (r'^deny', ' deny'), (r'^permit', ' permit'), (r'^ router', 'router'), (r'^neighbor', ' neighbor'), (r'^remark', ' remark'), (r'^or$', ' '), 
               (r'^switchport', ' switchport'), (r'(^\d{1,3})', r' \1'), (r' Interface', 'interface')
               ]
        for i in tup:
            item = re.sub(i[0], i[1], item)
        try:
            if len(item) > 0 and item not in show and not re.search(r'#show|# show', item):
                if item[0] != ' ':
                    key = item
                    setname(dictionary, key)
                else:
                    value = item
                    dictionary[key].append(value)
        except KeyError:
            continue
        except UnboundLocalError:
           continue

    for x,y in list(dictionary.items()):
        if len(y) > 1:
            dictionary[' '.join(x.split()[0:2])] = dictionary.pop(x)

    queryLine = ''
    config = 'pattern = ```\n'
    intCnt = 0
    configCnt = 1
    where = []
    for key in dictionary:
        """
        1. Creates unique query variables for each requirement
        2. Creates interface function to return a list of violating interfaces
        3. Formats query to search device configuration for pattern and return violating devices
        """
        if len(dictionary[key]) > 1 or (key.startswith('interface') and len(dictionary[key]) > 0):
            queryLine += '{} = ```\n'.format(key.replace(' ', '_').replace('.', '').replace('-', '_').replace('(', '').replace(')', ''))
            if 'interface' in key:
                if intCnt == 0:
                   intQuery += 'where !hasBlockMatch_alpha1(lines, {})'.format(key.replace(' ', '_').replace('.', '').replace('-', '_').replace('(', '').replace(')', ''))
                   query.append('let intViolation = interfaceViolation(device)')
                   intCnt =+ 1
                elif intCnt > 0:
                   intQuery += ' && !hasBlockMatch_alpha1(lines, {})'.format(key.replace(' ', '_').replace('.', '').replace('-', '_').replace('(', '').replace(')', ''))
            else:
                query.append('let config{} = max(blockMatches_alpha1(device.files.config, {}))'.format(configCnt, key.replace(' ', '_').replace('.', '').replace('-', '_').replace('(', '').replace(')', '')))
                configCnt += 1
            for o in dictionary[key]:
                if len(o) > 1:
                    queryLine += '{}\n'.format(o)
            queryLine += '```; \n'
        elif len(dictionary[key]) == 0:
            continue
        else:
            config += '{}\n'.format(key)
    config += '```;\n'
    if len(show) > 0 and len(config) > 19:
        config += 'show = ```\n{}\n```;\n'.format('\n'.join([i for i in show]))
        query.insert(2, custom)
        where.append('!isPresent(match)')
    elif len(show) > 0:
        config = 'show = ```\n{}\n```;\n'.format('\n'.join([i for i in show]))
        query.insert(2, custom)
        where.append('!isPresent(match)')
        queryLine += config
    elif len(config) > 19:
        queryLine += config
        query.append('let config = max(blockMatches_alpha1(device.files.config, pattern))')
        where.append('!isPresent(config)')
    if configCnt > 1:
        for i in range(1, configCnt):
            where.append('!isPresent(config{})'.format(i))    
    if intCnt > 0:
        intQuery += '\nselect interface;\n'
        query.insert(0, intQuery)  
        where.append('length(intViolation) > 0')  
        end = select2
    else:
        end = select1
    where = 'where '+' || '.join(i for i in where)
    if len(where) > 6:
       query.append(where)
    query.append(end)
    query = '\n'.join(i for i in query)
    return queryLine, query