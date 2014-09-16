import copy
import re
import random
import socket
import struct
import ipUtils
import ASAInfo
from bs4 import BeautifulSoup

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
                results = {'status': 'ok'}
                results.update({'resultXML': rawTestResult})
            else:
                results = {'status': 'error'}

            self.get('currentUnitTestACL').setTestResult(version, results)

    def _getXMLDataFromElement(self, s):
        return re.match(r'<[^>]+>(.*)</[^>]+>', s).group(1)

    def getTestReport(self, versionList, baselineVersion):
        returnStringList = []
        aclEntries = self.get('aclEntries')

        testHeaders = TestResult().getReportHeaders()
        rString = ''
        for h in testHeaders:
            rString = rString + ',"{' + h + '}"'



        for key in sorted(aclEntries.keys()):
            s = '"{}","{}","{}","{}"'.format(self.get('name'), key,
                                                      str(aclEntries[key]),
                                                      aclEntries[key].getUnitTest())

            if 'unitTest' not in aclEntries[key].keys():
                    tResults = TestResult().getReportTemplate()
                    tResults.update({'Action': 'N/A'})
                    s = s + rString.format(**tResults)
                    returnStringList.append(s)
                    continue

            tResults = aclEntries[key].getTestResult(baselineVersion)
            s = s + rString.format(**tResults)

            for version in versionList:
                if baselineVersion == version:
                    continue
                tResults = aclEntries[key].getTestResult(version)
                s = s + rString.format(**tResults)
                compare = aclEntries[key].compareResults(baselineVersion, version)
                s = s + ',"{}"'.format(compare)
            returnStringList.append(s)

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
            if destObj is not None and 'any' in destObj.keys():
                iList.extend(r.getAllInterfaces())
            elif destObj is not None and 'cidr' in destObj.keys():
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

    def changeDestinationIP(self, oldCIDR, newCIDR):
        if 'exactMatchedACLs' not in self.keys():
            self.update({'exactMatchedACLs': []})
        if 'netMatchedACLs' not in self.keys():
            self.update({'netMatchedACLs': []})
        exactMatchedACLs = self.get('exactMatchedACLs')
        netMatchedACLs = self.get('netMatchedACLs')
        for aclkey in self.get('aclEntries').keys():
            acl = self.get('aclEntries')[aclkey]
            match = acl.destinationMatches(oldCIDR)
            # make sure it is the top level ACL being updated
            if aclkey % 1 != 0:
                acl = self.get('aclEntries')[int(aclkey)]
            if match:
                acl.updateDestinationIP(newCIDR)
                if match == 'exact':
                    exactMatchedACLs.append(int(aclkey))
                else:
                    netMatchedACLs.append(int(aclkey))

    def getexactMatchedACLs(self):
        if 'exactMatchedACLs' in self.keys():
            return set(self.get('exactMatchedACLs'))

    def getnetMatchedACLs(self):
        if 'netMatchedACLs' in self.keys():
            return set(self.get('netMatchedACLs'))

    def getUpdatedACLs(self):
        aclEntries = self.get('aclEntries')
        retList = []

        allKeys = set([])
        if 'exactMatchedACLs' in self.keys():
            allKeys = allKeys.union(set(self.getexactMatchedACLs()))
        if 'netMatchedACLs' in self.keys():
            allKeys = allKeys.union(set(self.getnetMatchedACLs()))

        allKeys = sorted(allKeys, reverse=True)

        for key in allKeys:
            # netmatched takes precedence over exactmatch as object groups can contain both
            if  key in self.getnetMatchedACLs():
                retList.append(aclEntries[key].remark('Migration: More specific entries needed, original left intact'))
                newRules = aclEntries[key].getUpdatedACLs()
                retList.extend(newRules)
                retList.extend(aclEntries[key].getUpdatedACLs())
                if not newRules[0].startswith('object-group'):
                    retList.append(aclEntries[key].remark('Migration: Next {} rules(s) added as part of the migration'.format(len(newRules))))
            elif key in self.getexactMatchedACLs():
                retList.append(aclEntries[key].getInactive())
                retList.append(aclEntries[key].remark('Migration: Made inactive as exact replacement was found'))
                newRules = aclEntries[key].getUpdatedACLs()
                retList.extend(newRules)
                if not newRules[0].startswith('object-group'):
                    retList.append(aclEntries[key].remark('Migration: Next {} rules(s) added as part of the migration'.format(len(newRules))))

        if len(retList) > 0:
            return '\n'.join(retList)

    def rawTestResults(self):
        AEObj = self.get('aclEntries')
        for aclKey in AEObj:
            if 'unitTest' in AEObj[aclKey].keys():
                utVers = AEObj[aclKey]['unitTest']['versions']
                for version in utVers.keys():
                    if version == 'status':
                        continue
                    result = utVers[version].getRawResult()
                    if result is not None:
                        yield aclKey, version, result

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
        tResults = TestResult().getReportTemplate()
        tResults.update({'Action': 'N/A'})
        return tResults

    def setTestResult(self, version, testResult):
        return None

    def compareResults(self, version, testResult):
        return "N/A"

    def getDestinationIP(self):
        return None

    def getACEDetails(self):
        return None

    def destinationMatches(self, ip, protocol=None, port=None):
        return False

    def hasTestResult(self, version):
        return False
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
                self.update({'unitTest': ACLUnitTest(self)})
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
        if 'unitTest' in self.keys():
            self.get('unitTest').setUnitTest()

    def getUnitTest(self):
        if self.get('unitTest'):
            return self.get('unitTest').getUnitTestString()
        else:
            return 'N/A'
    def needsUnitTest(self, version):
        if 'unitTest' in self.keys():
            unitTestObj = self.get('unitTest')
            if version in unitTestObj['versions'].keys():
                return False
            else:
                return True
        else:
            return False

    def getRawResult(self, version):
        if version in self.get('unitTest')['versions']:
            return self.get('unitTest')['versions'][version].getRawResult()
        else:
            return None

    def getTestResult(self, version=None):
        return self.get('unitTest')['versions'][version].getReport()

    def compareResults(self, baselineVersion, version):
        v = self.get('unitTest')['versions']
        bSummary = v[baselineVersion].getSummary()
        vSummary = v[version].getSummary()

        if set(bSummary.items()) == set(vSummary.items()):
            return 'same'
        else:
            majorHeaders = set(['Ingress Int', 'Egress Int', 'Action',
                                'NAT Info', 'Drop Code'])
            diffLst = []
            for h in majorHeaders:
                if bSummary[h] != vSummary[h]:
                    diffLst.append(h)
            return 'different ({})'.format(', '.join(diffLst))

    def setTestResult(self, version, testResult):
        self.get('unitTest').addTestResult(version, testResult)

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

    def destinationMatches(self, cidr, protocol=None, port=None):
        dObj = self.get('destination')
        return dObj.matches(cidr)

    def updateDestinationIP(self, cidr):

        if 'newIPs' not in self.keys():
            self.update({'newIPs': {}})
        self.get('newIPs').update({cidr: True})

    def remark(self, string):
        return 'access-list {} line {} remark {}'.format( self.get('AclName'),
                                                          self.get('lineNum'),
                                                       string)

    def getUpdatedACLs(self):
        retList = []
        if 'protocol-object' in self.keys():
            protocol = "object-group {}".format(self.get('protocol-object'))
        elif 'service-object' in self.keys():
            protocol = "object-group {}".format(self.get('service-object'))
        else:
            protocol = self.get('protocol')
        aclString = 'access-list {} line {} extended {} {} {} {}'
        nwObjString = ' network-object {} {}'
        dObj = self.get('destination')
        if 'network-object' in dObj:
            objGrp = True
            retList.append('object-group network {}'.format(dObj.get('network-object')))
        else:
            objGrp = False
        for cidr in self.get('newIPs').keys():
            if objGrp:
                network, prefixLen = cidr.split('/')
                netmask = ipUtils.netmaskFromPrefixLength(prefixLen)
                string = nwObjString.format(network, netmask)
            else:
                newDest = copy.deepcopy(self.get('destination'))
                newDest.updateNetwork(cidr)
                string = aclString.format(self.get('AclName'), self.get('lineNum'),
                                             self.get('action'), protocol,
                                             self.get('source'), newDest)
            retList.append(string)
        return retList

    def getInactive(self):
        s = self.__repr__()
        return s + " inactive"


    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        if 'protocol-object' in self.keys():
            protocol = "object-group {}".format(self.get('protocol-object'))
        elif 'service-object' in self.keys():
            protocol = "object-group {}".format(self.get('service-object'))
        else:
            protocol = self.get('protocol')
        string = 'access-list {} line {} extended {} {} {} {}'.format( self.get('AclName'),
                                                                    self.get('lineNum'),
                                                                    self.get('action'),
                                                                    protocol,
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

    def matches(self, cidr, protocol=None, port=None):
        if self.get('network-object'):
            return False

        if port is not None and self.get('service-object'):
            return False

        if self.get('any') is not None:
            return False

        return ipUtils.CIDRMatch(cidr, self.get('cidr'))

    def updateNetwork(self, cidr):
        network, prefixLen = cidr.split('/')
        netmask = ipUtils.netmaskFromPrefixLength(prefixLen)
        self.update({'network': network,
                     'netmask': netmask})
        if prefixLen == '32':
            self.update({'host': True})

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

class ACLUnitTest(dict):
    def __init__(self, aceObj):
        self.update({'aceObj': aceObj})
        self.update({'versions': {}})
        self.update({'testParams': {}})

    def hasUnitTest(self, version):
        if version in self.get('versions').keys():
            return False
        else:
            return True

    def needsUnitTestSet(self):
        if len(self.get('testParams').keys()) > 0:
            return False
        else:
            return True

    def setUnitTest(self):
        if len(self.get('testParams').keys()) > 0:
            # if it already has parameters set, don't override them
            return

        aceObj = self.get('aceObj')
        aclObj = aceObj['parentObj']
        testParams = self.get('testParams')
        interface = aclObj['interface']
        interfaceCIDRList = aclObj['interfaceCIDRList']
        srcObj = aceObj.get('source')
        dstObj = aceObj.get('destination')
        protocol = aceObj.get('protocol')

        testParams.update({'interface': interface})

        srcIP = ASAInfo.getUnitTestIP(srcObj, interfaceCIDRList)
        dstIP = ASAInfo.getUnitTestIP(dstObj, ['8.8.8.8/32'])
        testParams.update({'srcIP': srcIP, 'dstIP': dstIP})
        if protocol in ['tcp', 'udp']:
            testParams.update({'protocol': protocol})
            srcPort = ASAInfo.getUnitTestPort(srcObj)
            dstPort = ASAInfo.getUnitTestPort(dstObj)
            testParams.update({'srcPort': srcPort, 'dstPort': dstPort})
        elif protocol in ['icmp', 'ip']:
            # Use ping test for "ip" based rules
            testParams.update({'protocol': 'icmp'})
            if 'icmpType' in aceObj.keys():
                icmpObj = aceObj.get('icmpType')
                icmpType, icmpCode = ASAInfo.getUnitTestICMP(icmpObj)
            else:
                icmpType = '8'
                icmpCode = '0'
            testParams.update({'icmpType': icmpType, 'icmpCode': icmpCode})
        else:
            protocol = ASAInfo.resolveIPProtocolType(protocol)
            testParams.update({'protocol': protocol})

    def addTestResult(self, version, results):
        versions = self.get('versions')
        versions.update({'status': results['status']})
        if results['status'] == 'ok':
            t = TestResult(results['resultXML'], self.get('testParams'))
            versions.update({version: t})
        else:
            versions.update({version: TestResult("Syntax Error",
                                             self.get('testParams'))})
    def getTestResult(self, version):
        return self.get('versions')[version].getReport()

    def getUnitTestString(self):
        tcpudp = "packet-tracer input {interface} {protocol} {srcIP} {srcPort} {dstIP} {dstPort} xml"
        icmp = "packet-tracer input {interface} icmp {srcIP} {icmpType} {icmpCode} {dstIP} xml"
        other = "packet-tracer input {interface} rawip {srcIP} {protocol} {dstIP} xml"
        testParams = self.get('testParams')
        if testParams['protocol'] in ['tcp', 'udp']:
            return tcpudp.format(**testParams)
        if testParams['protocol'] == 'icmp':
            return icmp.format(**testParams)
        else:
            return other.format(**testParams)

class TestResult(dict):

    def __init__(self, result=None, testParams=None):
        if result is not None and testParams is not None:
            self._processResult(result, testParams)
        else:
            if not result:
                "no result given"

            if not testParams:
                "no params given"

    def _processResult(self, result, testParams):
        if result == "Syntax Error":
            self.update({'action': result})
            return

        self.update({'rawResult': result})
        self.update({'testParams': testParams})
        soup = BeautifulSoup('<data>'+result+'</data>','xml')
        aclType=re.compile('(?i)access-list')
        natType=re.compile('(?i)nat')
        badSubType = re.compile(r'(?i)(rpf-check)|(host-limits)|(NAT-EXEMPT)')
        phaseAllow = re.compile(r'(?i)allow')
        phaseDrop = re.compile(r'(?i)drop')
        result = soup.findChildren('result')[-1]
        self.update({'action': result.action.text})
        phases = soup.findAll('Phase')
        if self.get('action') == 'drop':
            dropReason = result.find('drop-reason').text
            dropCode = re.search(r'\(([^\)]+)\)', dropReason).group(1)
            # Identify the section
            dropSections = [(p.type.text, p.subtype.text)
                            for p in phases if phaseDrop.search(p.result.text)]
            if len(dropSections) > 0:
                dropExtra = '{}'.format(dropSections[0][0])
                if dropSections[0][1] != '':
                    dropExtra = dropExtra + '/{}'.format(dropSections[0][1])
                dropExtra = dropExtra + ': '
                dropReason = dropExtra + dropReason
            self.update({'dropReason': dropReason})
            self.update({'dropCode': dropCode})

        if result.find('input-interface'):
            self.update({'ingressInt': result.find('input-interface').text})
        if result.find('output-interface'):
            self.update({'egressInt': result.find('output-interface').text})

        # Grab the ACL Information
        aclText = [p.config.text.strip() for p in phases if aclType.search(p.type.text)]
        if len(aclText) > 0:
            # Replace newlines with :
            aclText = re.sub(r'[\n\r]+', ': ', aclText[0])
            self.update({'aclText': aclText})

        '''
        this is a regular expression to capture the from ip(1)/port(2), to ip(3)/port(4)
        and optional netmask(5), examples below:
        Untranslate 203.202.141.0/0 to 203.202.141.0/0 using netmask 255.255.255.128
        Static translate 2.3.5.199/0 to 10.137.93.11/0 using netmask 255.255.255.255
        Static translate 2.3.5.199/1025 to 10.137.93.11/1025
        '''
        NATExtract = re.compile(r'((?:\d{1,3}\.){3}\d{1,3})/(\d+)\s+to\s+((?:\d{1,3}\.){3}\d{1,3})/(\d+)(?:\s+using\s+netmask\s+((?:\d{1,3}\.){3}\d{1,3}))?')

        '''
        Only relevant for < 8.3:
        these are regular expressions to capture the change in source IP from
        the examples below:
        nat (PoweronMgmt) 1 10.111.33.0 255.255.255.128
          match ip PoweronMgmt 10.111.33.0 255.255.255.128 outside any
            dynamic translation to pool 1 (61.88.171.148 [Interface PAT])
            translate_hits = 15, untranslate_hits = 0

        static (AW_EMC,MDNS) 161.43.223.10 161.43.223.10 netmask 255.255.255.255
          match ip AW_EMC host 161.43.223.10 MDNS any
            static translation to 161.43.223.10
            translate_hits = 0, untranslate_hits = 0

        need to compare the address from the match line and capture the new
        address from the pool
        '''
        s = r'\s+match\s+ip\s+' + self.get('ingressInt') + r'\s+((?:(?:\d{1,3}\.){3}\d{1,3})|(?:host))\s+((?:\d{1,3}\.){3}\d{1,3})'
        DynNATExtract = re.compile(r'\s+(?:(?:dynamic)|(?:static))\s+translation\s+to\s+(?:pool\s+\d+\s+\()?((?:\d{1,3}\.){3}\d{1,3})')
        DynNWExtract = re.compile(s)

        NATTranslations = [({'type': p.type.text,
                             'subtype': p.subtype.text,
                             'extra': p.extra.text,
                             'config': p.config.text})
                           for p in soup.findAll('Phase') \
                                if natType.search(p.type.text) and \
                                not badSubType.search(p.subtype.text) and \
                                phaseAllow.search(p.result.text)]
        for translation in NATTranslations:
            m = NATExtract.search(translation['extra'])
            n = DynNATExtract.search(translation['config'])
            if m is not None:
                fromInfo = m.group(1,2)
                toInfo = m.group(3,4)
                netmask = m.group(5)
                # If fromInto and toInfo are not the same, translation is ocurring
                if set(fromInfo) != set(toInfo):
                    match = self.matchesSrcOrDstIP(fromInfo[0], netmask)
                    matchKey = match + 'NAT'
                    if match == 'both':
                        "have a both match!"
                        print self.get('testParams')
                    self.update({matchKey: {}})
                    self.get(matchKey).update({'ip': self.translate(fromInfo[0],
                                                                    toInfo[0],
                                                                    netmask)})
                    if fromInfo[1] != toInfo[1]:
                        self.get(matchKey).update({'port': toInfo[1]})
            elif n is not None:
                o = DynNWExtract.search(translation['config'])
                if o.group(1) == 'host':
                    network = o.group(2)
                    netmask = '255.255.255.255'
                else:
                    network = o.group(1)
                    netmask = o.group(2)
                newIP = n.group(1)

                match = self.matchesSrcOrDstIP(network, netmask)
                matchKey = match + 'NAT'
                if match == 'both':
                        "have a both match!"
                        print self.get('testParams')
                self.update({matchKey: {}})
                self.get(matchKey).update({'ip': newIP})





    def getReportHeaders(self):
        return ['Ingress Int',
                'Egress Int',
                'Action',
                'NAT Info',
                'Drop Code',
                'Drop Reason',
                'ACL Text']

    def getReportTemplate(self):
        t = {}
        for h in self.getReportHeaders():
            t.update({h: ''})
        return t

    def getReport(self):
        report = self.getReportTemplate()
        if not self.get('action'):
            report.update({'Action': 'untested'})
            return report
        testParams = self.get('testParams')
        report.update({'Ingress Int': self.xstr(self.get('ingressInt'))})
        report.update({'Egress Int': self.xstr(self.get('egressInt'))})
        report.update({'Action': self.xstr(self.get('action'))})
        report.update({'Drop Code': self.xstr(self.get('dropCode'))})
        report.update({'Drop Reason': self.xstr(self.get('dropReason'))})
        report.update({'ACL Text': self.xstr(self.get('aclText'))})

        sNAT = self.getSrcNATBehaviour()
        dNAT = self.getDstNATBehaviour()

        report.update({'NAT Info': ' '.join([sNAT, dNAT])})
        return report

    def getRawResult(self):
        if self.get('rawResult'):
            return self.get('rawResult')
        else:
            return "No raw result recorded"

    def getSrcNATBehaviour(self):
        s = ''
        if self.get('sourceNAT'):
            origIP = self.get('testParams')['srcIP']
            newIP = self.get('sourceNAT').get('ip')
            origPort = ''
            newPort = ''
            ''' Kind of silly old school never really did source nat of ports
            if self.get('sourceNAT').get('port') and \
                    testParams['protocol'] in ['tcp','udp']:
                origPort = ":{}".format(testParams['srcPort'])
                newPort = ":{}".format(self.get('sourceNAT').get('port'))
            '''
            s = s+ 'srcNAT: {}{}->{}{}'.format(origIP, origPort, newIP, newPort)

        return s

    def getDstNATBehaviour(self):
        testParams = self.get('testParams')
        s = ''
        if self.get('destinationNAT'):
            if len(s) > 0:
                s = s + ' '
            origIP = testParams['dstIP']
            newIP = self.get('destinationNAT').get('ip')
            origPort = ''
            newPort = ''
            if self.get('destinationNAT').get('port')and \
                    testParams['protocol'] in ['tcp','udp']:
                origPort = ":{}".format(testParams['dstPort'])
                newPort = ":{}".format(self.get('destinationNAT').get('port'))
            s = s + 'dstNAT: {}{}->{}{}'.format(origIP, origPort, newIP, newPort)

        return s

    def getSummary(self):
        summary = self.getReport()
        # Remove un needed keys
        for k in ['Drop Reason', 'ACL Text']:
            summary.pop(k, None)

        return summary

    def xstr(self, s):
        if s is None:
            return ''
        else:
            return str(s)

    def translate(self, ip, network, netmask):
        if netmask is None or netmask == '255.255.255.255':
            # No translation is happening, network is final IP
            return network

        # Convert mask and network to int (validate the network based on mask)
        maskInt = ipUtils.aton(netmask)
        networkInt = ipUtils.aton(network) & maskInt
        # Work out the host mask
        hostBits = ~maskInt + 2**32
        # Get the host bits
        hostInt = ipUtils.aton(ip) & hostBits
        # Return the new IP address
        return ipUtils.ntoa(networkInt + hostInt)

    def matchesSrcOrDstIP(self, ip, netmask):
        if netmask is None:
            # Assume 32 bit mask if not supplied
            netmask = '255.255.255.255'
        ipInt = ipUtils.aton(ip)
        maskInt = ipUtils.aton(netmask)
        #print self.keys()
        srcIPInt = ipUtils.aton(self.get('testParams')['srcIP'])
        dstIPInt = ipUtils.aton(self.get('testParams')['dstIP'])
        matchesSrc = False
        matchesDst = False
        if ipInt & maskInt == srcIPInt & maskInt:
            matchesSrc = True
        if ipInt & maskInt == dstIPInt & maskInt:
            matchesDst = True

        if matchesSrc and matchesDst:
            return 'both'
        elif matchesSrc:
            return 'source'
        elif matchesDst:
            return 'destination'
        else:
            return None
