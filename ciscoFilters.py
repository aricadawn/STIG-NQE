import re
import custom_test as cs
from STIG_NQE import TOKEN

def fix_text(fix_content):
    '''
    Returns list of configurations from Fix Content section of STIG
    '''
    fix_lines = []
    for line in fix_content.splitlines():
        if re.search(r'#', line):
            fix_lines.append(line.split('#')[1].lstrip())
    
    for item in fix_lines:
        if re.match(r'end|exit', item):
            fix_lines.remove(item)
    return fix_lines

def check_vs_fix(checkLines, fix):
    '''
    Compares check content and fix content sections for whether config should be present in device
    '''
    config_lines = []
    config_lines_test = []
    for item in checkLines:
        if len(item) != 0:
            config_lines_test.append(item)
    disable = 0
    for line in fix:
        if line.startswith('no'):
            disable +=1
    if len(config_lines_test) == 0:
        config_lines = fix
    elif disable >= len(config_lines_test):
        config_lines = fix
    else:
        config_lines = checkLines
    return config_lines

def pattern(check_content, fix_content): 
    '''
    Filters Check Content portion of STIG to remove descriptions and collect configuration to create a list of pattern variables. 
    '''
    mode = False
    counter = False
    config_lines = []
    for line in check_content.splitlines():
        if not mode:
            if line.startswith(('Review', 'Step', 'Verify', 'Cisco router')) or line.endswith(('below:', 'example below.')):
                mode = True
        elif line.startswith('If'):
            mode = False
        else:
            if u'\u2026' not in line:
                config_lines.append(line)

    filters = [r'Example', r'example', r'Note', r'NOTE', r'Step', r'proceed', r'below', r'Verify', r'Review', r'Altern', r'https://', r'IF', r'!', r'[1-3]\. ', r'[2]\. ', r'command:'
               ]
    for word in filters:
        for item in config_lines:
            if re.findall(word, item):
                config_lines.remove(item)

    fix = fix_text(fix_content)
    config_lines = check_vs_fix(config_lines, fix)

    for index, item in enumerate(config_lines):
        if not counter:
            if item.startswith(('interface', ' interface', 'router ')):
                counter = True
        elif item == '':
            counter = False
        else:
            if item[0] != ' ' and not re.match(r'interface', item) and 'ip access-list' not in item:
                config_lines[index] = ' ' + item

    return config_lines

def reformat(config_lines):
    counter = False
    interfaceCnt = 1
    keyCnt = 1
    subnetCount = 1
    ipSubFilters = r'(x|\d{1,3})\.(x|\d{1,3})\.(x|\d{1,3})\.(x|\d{1,3})\/\d{1,4}'
    for index, item in enumerate(config_lines):
        item = item.rstrip()
        if item.startswith(('interface', ' interface', 'int')):
            config_lines[index] = '''interface {}'''.format(interfaceCnt)
            interfaceCnt += 1
        if 'key-string' in item:
            config_lines[index] = item.split('-')[0] + '-string {{key{}: string}}'.format(keyCnt)
            keyCnt += 1
        if 'ip address' in item:
            config_lines[index] = ''' ip address {ip: ipv4Address}'''
        if 'ipv6 address' in item:
            config_lines[index] = ''' ipv6 address {ip: ipv6Address}'''
        if 'description' in item:
            config_lines[index] = ''' description {desc: string}'''
        if 'hostname' in item:
            config_lines[index] = '''hostname {host: string}'''
        if re.search(r'( password \d \S{10,}| password \S{10,} )', item):
            config_lines[index] = re.sub(r'( password \d \S{10,}| password \S{10,} )', r' password {string} ', item)
        if re.search(r'( auth sha \S{10,})', item):
            config_lines[index] = re.sub(r'( auth sha \S{10,})', r' auth sha {string}', item)
        if re.search(r'( key \d \S{10,})', item):
            config_lines[index] = re.sub(r'( key \d \S{10,})', r' key {string}', item)
        if re.search(r'md5', item):
            config_lines[index] = re.sub(r'md5 .*', r'md5', item)
        if re.findall(ipSubFilters, item):
            subs = re.sub(ipSubFilters, '''{ipv4Subnet}''', item)
            config_lines[index] = re.sub(ipSubFilters, '''{ipv4Subnet}''', item)
            subnetCount += 2
        
        if not counter:
            if item.startswith(('interface', ' interface', 'router ')):
                counter = True
        elif item == '':
            counter = False
        else:
            if item[0] != ' ' and not re.match(r'interface', item) and 'ip access-list' not in item:
                config_lines[index] = ' ' + item

    ipFilters = r' ([xy]|\d{1,3})\.([xy]|\d{1,3})\.([xy]|\d{1,3}).([xy]|\d{1,3})'

    for num, item in enumerate(config_lines):
        '''
        1. Reformats items returned in pattern to match configuration syntax
        2. Creates dictionary of pattern variables 
        '''
        if re.search(ipFilters, item):
            config_lines[num] = re.sub(ipFilters, ' {ipv4Address}', item)
        if re.search(r'\[.*\]', item):
            config_lines[num] = re.sub(r'\[([a-zA-Z]+\s?)+\]', '{ipv4Address}', item)

    config_lines = [line for line in config_lines if len(line) > 1]

    return config_lines

def show_isPresent(config_lines, filtered, showCount):
    name = r'([A-Zo\d]+) ?(?:_[A-Z\d]+)+|([A-Z]{5,})'
    show = []
    isPresent = []
    custom = '''let outputs = device.outputs
foreach command in outputs.commands
where command.commandText == "{}"
let showOutput = parseConfigBlocks(device.platform.os, command.response)
let match = max(blockMatches_alpha1(showOutput, show))'''

    for num, item in enumerate(config_lines):
        if showCount == 0 :
            if re.search(r'show', item):
                showCount += 1
                if re.search(r'#', item):
                    item = re.sub(name, '', item)
                    cs.custom(item.split('#')[1].lstrip())
                    custom = custom.format(item.split('#')[1].lstrip())
                    # print(item)
                else:
                    custom = custom.format(item)
        elif item != '' and not re.search(r'#', item):
            show.append(item)

        if re.match('^no', item) and item not in isPresent:
            if filtered:
                if 'interface' in config_lines[num-1]:
                    isPresent.append('interface {{name{}:string}}'.format(1))
                    isPresent.append(item)
                else:
                    isPresent.append(item)
            else:
                if 'interface' in config_lines[num-1]:
                    isPresent.append(config_lines[num-1])
                    isPresent.append(item)
                else:
                    isPresent.append(item)                
    
    return show, isPresent, custom

def dictionary(pattern, filtered, count):

    if filtered:
        pattern  = reformat(pattern)

    show, isPresent, custom = show_isPresent(pattern, filtered, count)
    dictionary = {}
    def setname(d, n):
        if n.startswith('interface'):
           d[n] = []
        else:
           d[n] = [n]
    distinct = []   
    for i in isPresent:
        if i not in distinct:
            distinct.append(i.rstrip())
    for item in pattern:
        '''
        1. Reformats items returned in pattern to match configuration syntax
        2. Creates dictionary of pattern variables 
        '''
        tup = [(r' [nxyz]{2,}( |$)', ' '), (r'^deny', ' deny'), (r'^permit', ' permit'), (r'^neighbor', ' neighbor'), (r'^remark', ' remark'), (r'^or$', ' '), 
               (r'^switchport', ' switchport'), (r'(^\d{1,3})', r' \1'), (r'Interface', 'interface'), (r'\*{2,}', '')
               ]
        for i in tup:
            item = re.sub(i[0], i[1], item)
        try:
            if len(item) > 0 and item not in show and not re.search(r'show', item) and item not in isPresent:
                if item[0] != ' ':
                    key = item.rstrip()
                    setname(dictionary, key)
                else:
                    value = item.rstrip()
                    dictionary[key].append(value)
        except KeyError:
            continue
        except UnboundLocalError:
           continue
    
    newDictTest = []
    patternVars = {}
    for x,y in list(dictionary.items()):
        if x not in patternVars and y not in newDictTest:
            patternVars[x] = y
            newDictTest.append(y)
            if len(y) > 1:
                if 'ip access-list' not in x:
                    patternVars[' '.join(x.split()[0:2]).rstrip()] = patternVars.pop(x)
    return patternVars