import re
import random
import socket
import struct
import ipUtils
import ASAInfo

class AsaAcl (dict):
    def __init__ (self, AclList, objGrpObj):
        self.update({'objGrpObj': objGrpObj})
        self.update({'aclEntries': {}})
        self.update({'interface': '<interface>'})
        self.update({'interfaceCIDRList': []})
        self.update({'testResults': {}})

        parts = AclList[0].split()
        self.update({'name': parts[1]})

        LastAclMajNum = 0
        aclEntries = self.get('aclEntries')

        for line in AclList:
            parts = line.split()

            if parts[2] == 'remark':
                CurrAclMajNum = 0
                AclNumTrack = CurrAclMajNum
                AclType = 'remark'
                partsOffset = 3
            else:
                CurrAclMajNum = int(parts[3])
                AclType = parts[4]
                partsOffset = 5

            if CurrAclMajNum > LastAclMajNum:
                LastAclMajNum = CurrAclMajNum
                AclNumTrack = CurrAclMajNum
            else:
                AclNumTrack += 0.001


            if AclType == 'remark':
                string = ' '.join(parts[partsOffset:])
                aclObj = ACEInformational(self, CurrAclMajNum, AclType, string)
                aclEntries.update({AclNumTrack: aclObj})
            elif AclType == 'extended':
                aclObj = ACEExtended(self, CurrAclMajNum, AclType,
                                      parts[5:])
                aclEntries.update({AclNumTrack: aclObj})

    def setInterface(self, s):
        self.update({'interface': s})

    def setInterfaceCIDRList(self, l):
        self.update({'interfaceCIDRList': l})

    def setUnitTests(self):
        for k in self.get('aclEntries').keys():
            self.get('aclEntries')[k].setUnitTest()

    def _getUntestedACLs(self, version):
        aclEntries = self.get('aclEntries')
        aclEntryKeys=aclEntries.keys()
        return [n for n in aclEntryKeys if aclEntries[n].needsUnitTest(version)]

    def working(self):
        aclkeys = self.get('aclEntries').keys()
        for aclkey in aclkeys:
            print self.get('aclEntries')[aclkey].needsUnitTest(version='8.04')

    def numUnitTests(self, version):
        return len(self._getUntestedACLs(version))

    def unitTests(self, version):
        for k in sorted(self._getUntestedACLs(version)):
            self.update({'currentUnitTestACL': self.get('aclEntries')[k]})
            t = self.get('currentUnitTestACL').getUnitTest()
            if t is not None:
                yield t

    def setTestResults(self, version):
        validResultRe = re.compile(r'<action>(?:(?:allow)|(?:drop))')
        while True:
            rawTestResult = (yield)
            if validResultRe.search(rawTestResult):
                resultAsList = rawTestResult.split('\n')
                actionXML = [l for l in resultAsList
                             if l.startswith('<action>')][0]
                action = self._getXMLDataFromElement(actionXML)
                dropReason = ''
                if action == 'drop':
                    dropReasonXML = [l for l in resultAsList
                                     if l.startswith('<drop-reason>')][0]
                    dropReason = self._getXMLDataFromElement(dropReasonXML)

                testResults = {'action': action, 'reason': dropReason,
                               'rawResult': rawTestResult }
            else:
                testResults = {'action': 'unknown', 'reason': 'Test Failed',
                           'rawResult': rawTestResult }

            self.get('currentUnitTestACL').setTestResult(version, testResults)

    def _getXMLDataFromElement(self, s):
        return re.match(r'<[^>]+>(.*)</[^>]+>', s).group(1)

    def getTestReport(self, versionList):
        returnStringList = []
        aclEntries = self.get('aclEntries')
        for key in sorted(aclEntries.keys()):

            string = '"{}","{}","{}","{}"'.format(self.get('name'), key,
                                               str(aclEntries[key]),
                                               aclEntries[key].getUnitTest())
            for version in versionList:
                tResults = aclEntries[key].getTestResult(version)
                string = string + ',"{}","{}"'.format( tResults['action'],
                                                        tResults['reason'])

            returnStringList.append(string)

        return '\n'.join(returnStringList)

    def getDestinationInterfaces(self, routeTableObj, forIndex=None):
        r = routeTableObj
        AEObj = self.get('aclEntries')
        iList = []
        if forIndex is not None:
            keys = [k for k in AEObj.keys() if k >= forIndex and \
                                                k < forIndex + 1]
        else:
            keys = AEObj.keys()
        for k in keys:
            destObj = AEObj[k].get('destination')
            if destObj is not None and 'cidr' in destObj.keys():
                cidr = ipUtils.randomFromCIDRAddress(destObj['cidr'])
                i = r.getInterface(cidr)
                if i is not None:
                    iList.append(i)

        return set(iList)

    def getTopLevelACLs(self, getInterfaces=False, routeTableObj=None):
        AEObj = self.get('aclEntries')
        aclIndexes = sorted([i for i in AEObj.keys() if i % 1 == 0])
        for aclIndex in aclIndexes:
            ACLObj = AEObj[aclIndex]
            if isinstance(ACLObj, ACEExtended):
                if getInterfaces:
                    i = self.getDestinationInterfaces(routeTableObj, aclIndex)
                    yield ACLObj, i
                else:
                    yield ACLObj

    def __repr__(self):
        returnStringList = []
        aclEntries = self.get('aclEntries')
        for key in sorted(aclEntries.keys()):
            string = '"{}", "{}", "{}", "{}", "{}"'.format(self.get('name'), key,
                                                           "outcome",
                                                           "reason",
                                                           str(aclEntries[key]))
            returnStringList.append(string)

        return '\n'.join(returnStringList)

    def __str__(self):
        return self.__repr__()

    def __iter__(self):
        for key in sorted(self.get('aclEntries').keys()):
            yield self.get('aclEntries')[key]

class ACEObject(dict):
    '''
    basic ACE object for which all others are based upon.
    '''

    def getUnitTest(self):
        return None

    def setUnitTest(self):
        return None

    def needsUnitTest(self, version):
        return False

    def getTestResult(self, version=None):
        return {'action': 'N/A', 'reason': '', 'rawResult': ''}

    def setTestResult(self, version, testResult):
        return None

    def getDestinationIP(self):
        return None

    def getACEDetails(self):
        return None

class ACEInformational (ACEObject):

    def __init__(self, AclObj, l, t, s):
        self.update({'parentObj': AclObj})
        self.update({'AclName': self.get('parentObj')['name']})
        self.update({'lineNum': l})
        self.update({'type': t})
        self.update({'string': s})

    def __repr__(self):
        return "access-list {} line {} {} {}".format(self.get('AclName'),
                                                     self.get('lineNum'),
                                                     self.get('type'),
                                                     self.get('string'))

    def __str__(self):
        return self.__repr__()


class ACEExtended (ACEObject):

    def __init__(self, AclObj, l, t, eList):
        self.update({'parentObj': AclObj})
        self.update({'AclName': self.get('parentObj')['name']})
        self.update({'lineNum': l})
        self.update({'type': t})
        self.update({'testResults': {}})
        self.update({'eList': eList})
        keepList = " ".join(eList)
        parts = self.get('eList')

        self.update({'objGrpObj': self.get('parentObj')['objGrpObj']})

        self.update({'options': {}})
        options = self.get('options')
        while len(eList) > 0:
            part = parts.pop(0)
            if part in ['permit', 'deny']:
                self.update({'action': part})
            elif part in ASAInfo.validProtocolTypes.keys():
                    self.update({'protocol': part})
            elif part == 'object-group' and self.nextIsObjectGroup('protocol'):
                    self.update({'protocol-object': parts.pop(0)})
            elif part == 'object-group' and self.nextIsObjectGroup('service'):
                    self.update({'service-object': parts.pop(0)})
            elif part in ['host', 'any'] or ipUtils.isIPAddress(part) or \
                        (part == 'object-group' and \
                         self.nextIsObjectGroup('network')):
                if 'source' not in self.keys():
                    kwargs = {'type': 'source'}
                else:
                    kwargs = {'type': 'destination'}
                if part == 'object-group':
                    kwargs['network-object'] = parts.pop(0)
                elif ipUtils.isIPAddress(part):
                    kwargs['network'] = part
                    kwargs['netmask'] = parts.pop(0)
                elif part == 'host':
                    kwargs['network'] = parts.pop(0)
                    kwargs['netmask'] = '255.255.255.255'
                    kwargs['host'] = True
                elif part == 'any':
                    kwargs['network'] = '0.0.0.0'
                    kwargs['netmask'] = '0.0.0.0'
                    kwargs['any'] = True
                else:
                    print "have no idea what to do with {}".format(part)
                    print "host, any, ip:",
                    print keepList
                    continue

                if len(parts) > 0 and (parts[0] == 'object-group' and \
                                       self.nextIsObjectGroup('service',1)):
                        parts.pop(0)
                        kwargs['service-object'] = parts.pop(0)
                elif len(parts) > 0 and parts[0] in ASAInfo.validOperators:
                    kwargs['operator'] = parts.pop(0)
                    kwargs['portStart'] = parts.pop(0)
                    if kwargs['operator'] == 'range':
                        kwargs['portEnd'] = parts.pop(0)

                if kwargs['type'] == 'source':
                    self.update({'source':ACESrcDst(**kwargs)})
                else:
                    self.update({'destination':ACESrcDst(**kwargs)})
            elif (self.get('protocol') == 'icmp' and \
                          part in ASAInfo.validICMPTypes.keys()) or \
                          (part == 'object-group' and self.nextIsObjectGroup('icmp-type')):
                if part =='object-group':
                    kwargs['icmp-object'] = parts.pop(0)
                else:
                    kwargs['icmpType'] = part
                    if len(parts) > 0 and parts[0] in ASAInfo.validICMPCodes:
                        kwargs['icmpCode'] = parts.pop(0)
                self.update({'icmpType': ACEICMP(**kwargs)})
            elif part in ASAInfo.validACLOptions:

                if part in ['log']:
                    if parts[0] in ASAInfo.validLogLevels:
                        options.update({'log': parts.pop(0)})
                    else:
                        options.update({'log': True})
                    if parts[0] == 'interval':
                        parts.pop(0)
                        options.update({'interval': parts.pop(0)})
                elif part in ['time-range']:
                    options.update({'time-range': parts.pop(0)})
                else:
                    options.update({part: True})
            elif re.match(r'\(hitcnt=\d+\)', part):
                self.setUnitTest()
            elif re.match(r'^0x[a-fA-F0-9]{1,8}$', part):
                pass
            elif part in ['(inactive)']:
                pass
            else:
                print "have no idea what to do with {}".format(part)
                print "catch all"
                print keepList

    def nextIsObjectGroup(self, objType=None,index=0):
        o = self.get('objGrpObj')
        parts = self.get('eList')
        if o.isObjectGroup(parts[index]):
            returnFlag = True
            if objType is not None and \
                not o.objectGroupIsType(parts[index], objType):
                returnFlag = False
            return returnFlag
        else:
            return False

    def setUnitTest(self):
        self.update({'unitTest': self._getUnitTest()})

    def getUnitTest(self):
        if not self.get('needsUnitTest'): return

        if 'unitTest' in self.keys():
            return self.get('unitTest')
        else:
            return self._getUnitTest()

    def needsUnitTest(self, version):
        if not self.get('needsUnitTest'): return False

        if version in self.get('testResults').keys():
            return False
        else:
            return True


    def getTestResult(self, version=None):
        if not self.get('needsUnitTest'):
            return {'action': 'N/A', 'reason': '', 'rawResult': ''}

        untested = {'action': 'untested', 'reason': '', 'rawResult': ''}
        if 'testResults' in self.keys():
            if version is not None:
                if version in self.get('testResults').keys():
                    return self.get('testResults')[version]
                else:
                    return untested
            else:
                return self.get('testResults')
        else:
            return untested

    def setTestResult(self, version, testResult):
        self.get('testResults').update({version: testResult})

    def _getUnitTest(self):
        interface = self.get('parentObj')['interface']
        interfaceCIDRList = self.get('parentObj')['interfaceCIDRList']
        srcObj = self.get('source')
        dstObj = self.get('destination')
        protocol = self.get('protocol')
        srcIP = ASAInfo.getUnitTestIP(srcObj, interfaceCIDRList)
        dstIP = ASAInfo.getUnitTestIP(dstObj, ['8.8.8.8/32'])

        if protocol in ['tcp', 'udp']:
            srcPort = ASAInfo.getUnitTestPort(srcObj)
            dstPort = ASAInfo.getUnitTestPort(dstObj)

            return "packet-tracer input {} {} {} {} {} {} xml".format(
                                                            interface,
                                                            protocol,
                                                            srcIP, srcPort,
                                                            dstIP, dstPort)
        elif protocol in ['icmp']:
            icmpObj = self.get('icmpType')
            if 'icmpType' in self.keys():
                icmpType, icmpCode = ASAInfo.getUnitTestICMP(icmpObj)
            else:
                icmpType = '0'
                icmpCode = '0'

            return "packet-tracer input {} icmp {} {} {} {} xml".format(
                                                            interface, srcIP,
                                                            icmpType, icmpCode,
                                                            dstIP)
        elif protocol in ['ip']:
            return "packet-tracer input {} icmp {} 8 0 {} xml".format(
                                                            interface, srcIP,
                                                            dstIP)
        else:
            protocol = ASAInfo.resolveIPProtocolType(protocol)
            return "packet-tracer input rawip {} {} {} {} xml".format(
                                                            interface, srcIP,
                                                            protocol, dstIP)

    def getDestinationIP(self):
        return ipUtils.randomFromCIDRAddress(self.get('destination')['cidr'])

    def getACEDetails(self):
        src = self.get('source').getAddressForNAT()
        dst = self.get('destination').getAddressForNAT()

        returnkeys = ['protocol', 'protocol-object', 'service-object']
        prot = {}
        for key in set(self.keys()) & set(returnkeys):
            prot.update({key: self.get(key)})

        return {'protocol': prot, 'source': src, 'destination': dst}


    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        string = 'access-list {} line {} extended {} {} {}'.format( self.get('AclName'),
                                                                    self.get('lineNum'),
                                                                    self.get('protocol'),
                                                                    self.get('source'),
                                                                    self.get('destination'))
        if 'icmpType' in self.keys():
            string = string + ' {}'.format(self.get('icmpType'))

        return string

class ACEProtocol(dict):
    def __init__(self, **kwargs):
        for k, v in kwargs.iteritems():
            self.update({k: v})

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        if 'protocol-object' in self.keys():
            s = 'object-group {}'.format(self.get('protocol-object'))
        else:
            s = self.get('protocol')

        return s

class ACESrcDst(dict):
    def __init__(self, **kwargs):
        for k, v in kwargs.iteritems():
            self.update({k: v})

        if 'network-object' not in self.keys():
            cidr = ipUtils.CIDRfromNetworkNetmask(self['network'],
                                                  self['netmask'])
            prefixLen = ipUtils.prefixLenFromNetmask(self['netmask'])
            self.update({'prefixLen': prefixLen})
            self.update({'cidr': cidr})
            self.update({'nwInt': ipUtils.aton(self['network'])})
            self.update({'maskInt': ipUtils.aton(self['netmask'])})

            if self.get('cidr')  == "0.0.0.0/0":
                self.update({'any': True})

    def getRandomIP(self, routeCidrList=None):
        if 'network-object' not in self.keys():
            return ipUtils.randomFromCIDRAddress(self.get('cidr'))

    def getAddressForNAT(self):
        returnkeys = ['host', 'any', 'cidr', 'network', 'netmask',
                      'network-object', 'service-object', 'operator',
                      'portStart', 'portEnd']
        d = {}
        for key in set(self.keys()) & set(returnkeys):
            d.update({key: self.get(key)})

        return d

    def __repr__(self):
        if 'network-object' in self.keys():
            s = 'object-group {}'.format(self.get('network-object'))
        elif 'any' in self.keys():
            s = 'any'
        elif 'host' in self.keys():
            s = 'host {}'.format(self.get('network'))
        else:
            s = '{} {}'.format(self.get('network'), self.get('netmask'))

        if 'service-object' in self.keys():
            s = s + ' object-group {}'.format(self.get('service-object'))
        elif 'operator' in self.keys():
            s = s + ' {} {}'.format(self.get('operator'), self.get('portStart'))
            if self.get('operator') == 'range':
                s = s + ' {}'.format(self.get('portEnd'))

        return s

    def __str__(self):
        return self.__repr__()


class ACEICMP(dict):
    def __init__(self, **kwargs):
        for k, v in kwargs.iteritems():
            self.update({k: v})

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        if 'icmp-object' in self.keys():
            s = 'object-group {}'.format(self.get('icmp-object'))
        else:
            s = self.get('icmpType')
            if 'icmpCode' in self.keys():
                s = s + ' {}'.format(self.get('icmpCode'))
        return s
