import re

def text(fix_content):
    '''
    Returns list of configurations from Fix Content section of STIG
    '''
    lines = []
    for line in fix_content.splitlines():
        if re.search(r'#', line):
            lines.append(line.split('#')[1].lstrip())
    
    for item in lines:
        if re.match(r'end|exit', item):
            lines.remove(item)
    return lines

def test(checkLines, fix):
    '''
    Compares check content and fix content sections for whether config should be present in device
    '''
    lines = []
    linesTest = []
    for item in checkLines:
        if len(item) != 0:
            linesTest.append(item)
    disable = False
    for line in fix:
        if line.startswith('no'):
            disable = True
    if len(linesTest) == 0:
        lines = fix
    elif disable:
        lines = fix
    else:
        lines = checkLines
    return lines

def pattern(check_content, fix_content): 
    '''
    Filters Check Content portion of STIG to remove descriptions and collect configuration to create a list of pattern variables. 
    '''
    mode = False
    lines = []
    for line in check_content.splitlines():
        if not mode:
            if line.startswith(('Review', 'Step', 'Verify', 'Cisco router')) or line.endswith(('below:', 'example below.')):
                mode = True
        elif line.startswith('If'):
            mode = False
        else:
            if u'\u2026' not in line:
                lines.append(line)

    filters = [r'Example', r'example', r'Note', r'NOTE', r'Step', r'proceed', r'below', r'Verify', r'Review', r'Altern', r'https://', r'IF', r'!', r'[1-3]\. ', r'[2]\. ', r'command:'
               ]
    for word in filters:
        for item in lines:
            if re.findall(word, item):
                lines.remove(item)

    fix = text(fix_content)
    lines = test(lines, fix)
    counter = False
    interfaceCnt = 1
    keyCnt = 1
    ipAddCnt = 1
    passCount = 1
    subnetCount = 1
    ipSubFilters = r'(x|\d{1,3})\.(x|\d{1,3})\.(x|\d{1,3})\.(x|\d{1,3})\/\d{1,4}'
    for index, item in enumerate(lines):
        item = item.rstrip()
        if item.startswith(('interface', ' interface', 'int')):
            lines[index] = '''interface {}'''.format(interfaceCnt)
            interfaceCnt += 1
        if 'key-string' in item:
            lines[index] = ''.join(item.rsplit(' ', 1)[0]) + ' {{key{}: string}}'.format(keyCnt)
            keyCnt += 1
        if 'ip address' in item:
            lines[index] = ''' ip address {ip: ipv4Address}'''
            ipAddCnt += 1
        if 'description' in item:
            lines[index] = ''' description {desc: string}'''
        if 'hostname' in item:
            lines[index] = '''hostname {host: string}'''
        if 'password' in item:
            if re.search(r'( password \d [a-z0-9]{10,}| password [a-z0-9]+ )', item):
                lines[index] = re.sub(r'( password \d [a-z0-9]{10,}| password [a-z0-9]+ )', r' password {{password{}: string}} '.format(passCount), item)
            else:
                lines[index] = re.sub(r'password ', r'password {{password{}: string}} '.format(passCount), item)
            passCount += 1
        if re.findall(ipSubFilters, item):
            subs = re.sub(ipSubFilters, '''{{subnet{}: ipv4Subnet}}''', item)
            lines[index] = subs.format(subnetCount, subnetCount + 1)
            subnetCount += 2
        
        if not counter:
            if item.startswith(('interface', ' interface', 'router ')):
                counter = True
        elif item == '':
            counter = False
        else:
            if item[0] != ' ' and not re.match(r'interface', item) and 'ip access-list' not in item:
                lines[index] = ' ' + item
        
    
    return lines

def dictionary(pattern):
    '''
    1. Creates a dictionary of pattern variables by filtering through list created in pattern function.
    2. Returns pattern variables and formatted query as strings 
    '''

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
select {{
  violation: {},
  device: device.name,
  deviceModel: device.platform.model,
  mgmtIP: device.platform.managementIps,
  Severity: stigData.severity,
  Group_Title: stigData.groupTitle,
  Vuln_ID: stigData.vulnId,
  Rule_ID: stigData.ruleId,
  Rule_Version: stigData.ruleVersion
}}'''
    select2 = '''
select {{
  violation: {},
  device: device.name,
  interface: (foreach int in intViolation select int.data.name),
  deviceModel: device.platform.model,
  mgmtIP: device.platform.managementIps,
  Severity: stigData.severity,
  Group_Title: stigData.groupTitle,
  Vuln_ID: stigData.vulnId,
  Rule_ID: stigData.ruleId,
  Rule_Version: stigData.ruleVersion
}}'''

    custom = '''let outputs = device.outputs
foreach command in outputs.commands
where command.commandText == "{}"
let showOutput = parseConfigBlocks(device.platform.os, command.response)
let match = max(blockMatches_alpha1(showOutput, show))'''

    show = []
    isPresent = []
    showCount = 0

    dictionary = {}
    def setname(d, n):
        if n.startswith('interface'):
           d[n] = []
        else:
           d[n] = [n]

    pattern = [z for z in pattern if len(z) > 1]
    ipCnt = 1
    for num, item in enumerate(pattern):
        '''
        1. Reformats items returned in pattern to match configuration syntax
        2. Creates dictionary of pattern variables 
        '''
        ipFilters = r' (x|\d{1,3})\.(x|\d{1,3})\.(x|\d{1,3}).(x|\d{1,3})'
        name = r' ([A-Z\d]+(?:_[A-Z\d]+)+)'
        if re.search(ipFilters, item):
            subs = re.sub(ipFilters, ' {{ip{}: ipv4Address}}', item)
            try:
                item = subs.format(ipCnt, ipCnt + 1)
            except IndexError:
                continue
            except KeyError:
                continue
            ipCnt += 2
        tup = [(r' [nxyz]{2,}', ' '), (r'^deny', ' deny'), (r'^permit', ' permit'), (r'^neighbor', ' neighbor'), (r'^remark', ' remark'), (r'^or$', ' '), 
               (r'^switchport', ' switchport'), (r'(^\d{1,3})', r' \1'), (r'Interface', 'interface'), (r'\*{2,}', '')
               ]
        for i in tup:
            item = re.sub(i[0], i[1], item)

        if showCount == 0 :
            # if re.search(r'#show|# show', item):
            if re.search(r'show', item):
                showCount += 1
                if re.search(r'#', item):
                    custom = custom.format(item.split('#')[1].lstrip())
                else:
                    custom = custom.format(item)
        elif item != '' and not re.search(r'#', item):
            show.append(item)    
        if re.match('^no', item) and item not in isPresent:
            if 'interface' in pattern[num-1]:
                isPresent.append('interface {{name{}:string}}'.format(1))
                isPresent.append(item)
            else:
                isPresent.append(item)
        
        try:
            if len(item) > 0 and item not in show and not re.search(r'show', item) and item not in isPresent:
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
    
    newDictTest = []
    patternVars = {}
    for x,y in list(dictionary.items()):
        if y not in newDictTest:
            patternVars[x] = y
            newDictTest.append(y)
            if len(y) > 1:
                patternVars[' '.join(x.split()[0:2])] = patternVars.pop(x)
    distinct = []   
    for i in isPresent:
        if i not in distinct:
            distinct.append(i.rstrip())

    queryLine = ''
    config = 'pattern = ```\n'
    intCnt = 0
    nameCnt = 1
    configCnt = 1
    where = []
    for key in patternVars:
        '''
        1. Creates unique query variables for each requirement
        2. Creates interface function to return a list of violating interfaces
        3. Formats query to search device configuration for pattern and return violating devices
        '''
        if (len(patternVars[key]) > 2 or (key.startswith('interface') and len(patternVars[key]) > 0)):
            queryLine += '{} = ```\n'.format(key.split('{')[0].rstrip().replace(' ', '_').replace('.', '').replace('-', '_').replace('(', '').replace(')', ''))
            if 'interface' in key:
                if intCnt == 0:
                   intQuery += 'where !hasBlockMatch_alpha1(lines, {})'.format(key.replace(' ', '_').replace('.', '').replace('-', '_').replace('(', '').replace(')', ''))
                   query.append('let intViolation = interfaceViolation(device)')
                   intCnt =+ 1
                elif intCnt > 0:
                   intQuery += ' && !hasBlockMatch_alpha1(lines, {})'.format(key.replace(' ', '_').replace('.', '').replace('-', '_').replace('(', '').replace(')', ''))
            else:
                query.append('let config{} = max(blockMatches_alpha1(device.files.config, {}))'.format(configCnt, key.split('{')[0].rstrip().replace(' ', '_').replace('.', '').replace('-', '_').replace('(', '').replace(')', '')))
                configCnt += 1
            for o in patternVars[key]:
                if len(o) > 1:
                    # o = re.sub(name, r' {\1:string}', o)
                    queryLine += '{}\n'.format(o)
            queryLine += '```; \n'
        elif len(patternVars[key]) == 0:
            continue
        else:
            config += '{}\n'.format('\n'.join([i for i in patternVars[key]]))
    config += '```;\n'
    if len(config) > 19:
        if len(show) > 0:
            config += 'show = ```\n{}\n```;\n'.format('\n'.join([i for i in show]))
            query.insert(2, custom)
            where.append('!isPresent(match)')    
        if len(isPresent) > 0:
            config += 'disable = ```\n{}\n```;\n'.format('\n'.join([i.lstrip('no') for i in distinct]))
            query.append('let disableConfig = max(blockMatches_alpha1(device.files.config, disable))')
            where.append('isPresent(disableConfig)')     
        queryLine += config
        query.append('let config = max(blockMatches_alpha1(device.files.config, pattern))')
        where.append('!isPresent(config)')
    else:
        if len(show) > 0:
            config = 'show = ```\n{}\n```;\n'.format('\n'.join([i for i in show]))
            query.insert(2, custom)
            where.append('!isPresent(match)')    
            queryLine += config
        if len(isPresent) > 0:
            config = 'disable = ```\n{}\n```;\n'.format('\n'.join([i.lstrip('no') for i in distinct]))
            query.append('let disableConfig = max(blockMatches_alpha1(device.files.config, disable))')
            where.append('isPresent(disableConfig)')
            queryLine += config
        
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
    # where = 'where '+' || '.join(i for i in where)
    # if len(where) > 6:
    #    query.append(where)
    if len(where) > 0:
        end = end.format(' || '.join(i for i in where))
    else:
        end = end.format('isPresent(device.name)')
    query.append(end)
    query = '\n'.join(i for i in query)
    return queryLine, query