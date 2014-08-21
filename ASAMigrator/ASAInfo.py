import random
import ipUtils

validProtocolTypes = {'ah': '51', 'eigrp': '88', 'esp': '50', 'gre': '47',
                      'icmp': '1', 'icmp6': '58', 'igmp': '2', 'igrp': '9',
                      'ip': '0', 'ipinip': '4', 'ipsec': '50', 'nos': '94',
                      'ospf': '89', 'pcp': '108', 'pim': '103', 'pptp': '47',
                      'snp': '109', 'tcp': '6', 'udp': '17'}

validOperators = [ 'eq' ,'gt', 'lt', 'neq', 'range']

validICMPTypes = {'echo-reply': '0', 'unreachable': '3', 'source-quench': '4',
                  'redirect': '5', 'alternate-address': '6', 'echo': '8',
                  'router-advertisement': '9', 'router-solicitation': '10',
                  'time-exceeded': '11', 'parameter-problem': '12',
                  'timestamp-request': '13', 'timestamp-reply': '14',
                  'information-request': '15', 'information-reply': '16',
                  'mask-request': '17', 'mask-reply': '18', 'traceroute': '30',
                  'conversion-error': '31', 'mobile-redirect': '32'}

validTCPUDPProtocols = { 'aol': '5190', 'bgp': '179', 'biff': '512',
                         'bootpc': '68', 'bootps': '67', 'chargen': '19',
                         'citrix-ica': '1494', 'cmd': '514',
                         'ctiqbe': '2748', 'daytime': '13', 'discard': '9',
                         'domain': '53', 'dnsix': '195', 'echo': '7',
                         'exec': '512', 'finger': '79', 'ftp': '21',
                         'ftp-data': '20', 'gopher': '70', 'https': '443',
                         'h323': '1720', 'hostname': '101', 'ident': '113',
                         'imap4': '143', 'irc': '194', 'isakmp': '500',
                         'kerberos': '750', 'klogin': '543',
                         'kshell': '544', 'ldap': '389', 'ldaps': '636',
                         'lpd': '515', 'login': '513', 'lotusnotes': '1352',
                         'mobile-ip': '434', 'nameserver': '42',
                         'netbios-ns': '137', 'netbios-dgm': '138',
                         'netbios-ssn': '139', 'nntp': '119', 'ntp': '123',
                         'pcanywhere-status': '5632',
                         'pcanywhere-data': '5631', 'pim-auto-rp': '496',
                         'pop2': '109', 'pop3': '110', 'pptp': '1723',
                         'radius': '1645', 'radius-acct': '1646',
                         'rip': '520', 'secureid-udp': '5510',
                         'smtp': '25', 'snmp': '161', 'snmptrap': '162',
                         'sqlnet': '1521', 'ssh': '22',
                         'sunrpc (rpc)': '111', 'syslog': '514',
                         'tacacs': '49', 'talk': '517', 'telnet': '23',
                         'tftp': '69', 'time': '37', 'uucp': '540',
                         'who': '513', 'whois': '43', 'www': '80',
                         'xdmcp': '177' }

validICMPCodes = str(range(16))

validACLOptions = ['log', 'time-range' , 'interval', 'inactive' ]

validLogLevels = [ 'alerts', 'critical', 'debugging', 'emergencies',
                  'errors', 'informational', 'notifications', 'warnings']
validLogLevels.extend(str(range(8)))

def resolveTCPUDPProtocolType(string):
    if string.isdigit():
        return string
    else:
        if string in validTCPUDPProtocols.keys():
            return validTCPUDPProtocols[string]
        else:
            return '65635'

def resolveIPProtocolType(string):
    if string.isdigit():
        return string
    else:
        if string in validProtocolTypes.keys():
            return validProtocolTypes[string]
        else:
            return '0'

def _portBelow(p):
    return str(random.randint(0, int(p)))

def _portAbove(p):
    return str(random.randint(int(p), 65535))

def _portBetween(p1, p2):
    return str(random.randint(int(p1), int(p2)))

def _notPort(p):
    if int(p) > 32765:
        return _portBelow(p)
    else:
        return _portAbove(p)

def getUnitTestPort(ACEObj):
    if 'operator' in ACEObj.keys():
        portS = resolveTCPUDPProtocolType(ACEObj.get('portStart'))
        if ACEObj.get('operator') == 'range':
                portE = resolveTCPUDPProtocolType(ACEObj.get('portEnd'))
                return _portBetween(portS, portE)
        elif ACEObj.get('operator') == 'lt':
            return _portBelow(portS)
        elif ACEObj.get('operator') == 'gt':
            return _portAbove(portS)
        elif ACEObj.get('operator') == 'neq':
            return _notPort(portS)
        else:
            return ACEObj.get('portStart')
    else:
        return random.randint(16385, 32767)

def getUnitTestIP(ACEObj, sourceCIDRList=None):
    if hasattr(ACEObj, 'any'):
        if sourceCIDRList is not None:
            return ipUtils.randomFromCIDRAddress(random.choice(sourceCIDRList))
        else:
            return '1.1.1.1'
    else:
        return ACEObj.getRandomIP()

def getUnitTestICMP(icmpObj):
    icmpType = icmpObj.get('icmpType')
    if not icmpType.isdigit():
        icmpType = validICMPTypes[icmpType]

    if 'icmpCode' in icmpObj.keys():
        icmpCode = icmpObj.get('icmpCode')
    else:
        icmpCode = '0'

    return icmpType, icmpCode

def getRawConfigBlockFromIndex(clist, index, numSpaces=1):
        indent = " " * numSpaces

        linesFromBlockEnd =  [i for i, line in
               enumerate(clist[index:])
               if not line.startswith(indent)][1]
        endOfBlockIndex = index + linesFromBlockEnd

        return clist[index:endOfBlockIndex]