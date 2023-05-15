import re
import ciscoFilters

def query_creator(patternVars, show, isPresent, custom, filtered):

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
    distinct = []   
    for i in isPresent:
        if i not in distinct:
            distinct.append(i.rstrip())

    name = r'([A-Zo\d]+) ?(?:_[A-Z\d]+)+|([A-Z]{5,})'
    queryLine = ''
    config = 'pattern = ```\n'
    intCnt = 0
    configCnt = 1
    nameList = []
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
                    if filtered:
                        if re.search(name, o):
                            vary = re.search(name, o)
                            if vary.group(0) not in nameList:
                                nameList.append(vary.group(0))
                        o = re.sub(name, r'{string}', o)
                    queryLine += '{}\n'.format(o)
            queryLine += '```; \n'
        elif len(patternVars[key]) == 0:
            continue
        else:
            if filtered:
                config += '{}\n'.format('\n'.join([re.sub(name, r'{string}', i) for i in patternVars[key]]))
            else:
                config += '{}\n'.format('\n'.join([i for i in patternVars[key]]))
    config += '```;\n'
    if len(config) > 19:
        if len(show) > 0:
            config += 'show = ```\n{}\n```;\n'.format('\n'.join([i for i in show]))
            query.insert(2, custom)
            where.append('!isPresent(match)')    
        if len(isPresent) > 0:
            if filtered:
                config += 'disable = ```\n{}\n```;\n'.format('\n'.join([re.sub(name, r'{string}', i.lstrip('no ')) for i in distinct]))
            else:
                config += 'disable = ```\n{}\n```;\n'.format('\n'.join([i.lstrip('no ') for i in distinct]))
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
            if filtered:
                config += 'disable = ```\n{}\n```;\n'.format('\n'.join([re.sub(name, r'{string}', i.lstrip('no ')) for i in distinct]))
            else:
                config += 'disable = ```\n{}\n```;\n'.format('\n'.join([i.lstrip('no ') for i in distinct]))
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

def cust_config(cust, pattern, filtered):
    cust_show = ciscoFilters.show_isPresent(cust, False, 1)
    pattern_show = ciscoFilters.show_isPresent(pattern, True, 0)

    if len(pattern_show[0]) > 0:
        show = cust_show[0]
        custom = pattern_show[2]
        count = 1
    else:
        show = []
        custom = ''
        count = 0

    if len(pattern_show[1]) > 0:
        isPresent = cust_show[1]
    else:
        isPresent = []

    patternVars = ciscoFilters.dictionary(cust, filtered, count)
    query = query_creator(patternVars, show, isPresent, custom, filtered)

    return query

def stig_pattern(check_lines):
    patternVars = ciscoFilters.dictionary(check_lines, True, 0)
    pattern_show = ciscoFilters.show_isPresent(check_lines, True, 0)
    query = query_creator(patternVars, pattern_show[0], pattern_show[1], pattern_show[2], True)

    return query

# def stig_pattern(check_lines):
#     patternVars = filters2.dictionary(check_lines, False, 0)
#     pattern_show = filters2.show_isPresent(check_lines, False, 0)
#     query = query_creator(patternVars, pattern_show[0], pattern_show[1], pattern_show[2], False)

#     return query