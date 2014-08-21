validProtocolTypes = ['ah', 'eigrp', 'esp', 'gre', 'icmp', 'icmp6', 'igmp',
                     'igrp', 'ip', 'ipinip', 'ipsec', 'nos', 'ospf',
                     'pcp', 'pim', 'pptp', 'snp', 'tcp', 'udp']

validOperators = [ 'eq' ,'gt', 'lt', 'neq', 'range']

validICMPTypes = {'echo-reply': '0',
                  'unreachable': '3',
                  'source-quench': '4',
                  'redirect': '5',
                  'alternate-address': '6',
                  'echo': '8',
                  'router-advertisement': '9',
                  'router-solicitation': '10',
                  'time-exceeded': '11',
                  'parameter-problem': '12',
                  'timestamp-request': '13',
                  'timestamp-reply': '14',
                  'information-request': '15',
                  'information-reply': '16',
                  'mask-request': '17',
                  'mask-reply': '18',
                  'traceroute': '30',
                  'conversion-error': '31',
                  'mobile-redirect': '32'}

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

validOptions = ['inactive', 'log', 'time-range' , 'interval' ]

validLogLevels = [ 'alerts', 'critical', 'debugging', 'emergencies',
                  'errors', 'informational', 'notifications', 'warnings']
validLogLevels.extend(str(range(8)))