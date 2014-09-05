import os
import pickle
import re
import sys
import time
from AsaACL import *
from AsaNat import *
from AsaObjGrp import *
from RouteTable import *
from ipUtils import *

class ASAProcessor():

    config = {'source': 'ASAProcessor'}
    config['baselineVersion'] = None
    config['osVersions'] = []
    config['interfaceMappings'] = {}
    config['accessLists'] = {}
    config['nat'] = {}

    stateSave = 'ASAProcessorState.pkl'
    useCache = True
    #iOverride = ['ahm']


    def __init__(self, i, saveState=True):
        self.interactor = i
        self.saveState = saveState
        return

    def __enter__(self):
        if os.path.isfile(self.stateSave):
            with open(self.stateSave) as f:
                obj = pickle.load(f)
                if isinstance(obj, dict) \
                        and 'source' in obj.keys() \
                        and obj['source'] == 'ASAProcessor':
                    self.config = obj
                    print "Sucessfully loaded previous state"

        return self

    def __exit__(self, type, value, traceback):
        if self.saveState:
            f = open(self.stateSave, 'wb')
            try:
                print "saving state"
                pickle.dump(self.config, f, pickle.HIGHEST_PROTOCOL)
                print "state saved"
            except:
                print "Unable to save state!"
            return

    def _listFilter(self, lst, regex, include=True):
        r = re.compile(regex)
        if include:
            indexes = [i for i, line in enumerate(lst) if r.search(line)]
        else:
            indexes = [i for i, line in enumerate(lst) if not r.search(line)]
        newlst = []
        for i in indexes:
            newlst.append(lst[i])
        return newlst

    def updateOsVersions(self, isBaseline=False):
        showVer = self.interactor.runcmd('show version')
        version = [l for l in showVer if 'Software Version' in l][0].split()[-1]
        version = re.sub(r'[()]', '', version)
        if isBaseline:
            self.config['baselineVersion'] = version
        if 'baselineVersion' not in self.config.keys():
            self.config['baselineVersion'] = '8.02'
        self.config['osVersions'].append(version)
        self.config['osVersions'] = list(set(self.config['osVersions']))
        self.config['osVersions'].sort()
        self.currentVersion = version
        return version

    def updateRouteTable(self):

        if 'routeTable' in self.config.keys() and self.useCache:
            print "Using cached routetable data"
        else:
            showRoute = self.interactor.runcmd('show route')
            routeTable = RouteTable(showRouteList=showRoute)
            self.config['routeTable'] = routeTable

        return self.config['routeTable']

    def updateObjectGroups(self):
        if 'objectGroups' in self.config.keys() and self.useCache:
            print "Using cached Object Group data"
            return

        showObj = self.interactor.runcmd('show running-config object-group', timeout=60)
        objGrpObj = AsaObjGrp()
        objGrpObj.createGroupsFromConfig(showObj)
        self.config['objectGroups'] = objGrpObj

    def updateAccessLists(self):
        accessLists = self.config['accessLists']

        objGrpObj = self.config['objectGroups']
        if self.useCache:
            ACLs = [a for a in self.getAccessLists()
                    if a not in accessLists.keys()]
        else:
            ACLs = self.getAccessLists()
        for ACL in ACLs:
            aclList = self.getShowAccessList(ACL)
            aclObj = AsaAcl(aclList, objGrpObj)
            accessLists.update({ACL: aclObj})

    def updateAccessGroupMappings(self):
        accessGroupCfgLst = self.interactor.runcmd('show running-config access-group')
        accessGroupCfgLst = self._listFilter(accessGroupCfgLst, r'^access')

        accessLists = self.config['accessLists']
        iMappings = self.config['interfaceMappings']
        for item in accessGroupCfgLst:
            parts = item.split()
            ACLName = parts[1]
            interface = parts[4]
            #if interface in self.config['interfaceMappings'].keys():
            #    pass
            #else:
            iMappings.update({interface: {'acl': ACLName,
                                          'aclObj': accessLists[ACLName]}})

    def prepareUnitTests(self):
        interfaces = self._getUnitTestInterfaceNames()
        iMappings = self.config['interfaceMappings']
        #for i in iMappings:
        #    print type(i)
        r = self.config['routeTable']
        for interface in iMappings.keys():
            aclObj = iMappings[interface]['aclObj']
            aclObj.setInterface(interface)
            aclObj.setInterfaceCIDRList(r.getCIDRbyInterface(interface))
            aclObj.setUnitTests()

    def getShowAccessList(self, aclName):
        aclList = self.interactor.runcmd('show access-list {}'.format(aclName), timeout=60)
        aclList = self._listFilter(aclList, r'^\s*access-list')
        aclList = self._listFilter(aclList, r'^access-list.*; \d+ elements$', include=False)
        aclList = self._listFilter(aclList, r'^access-list cached ACL log flows', include=False)
        print "{} entries for access-list {}".format(len(aclList), aclName)
        return aclList

    def getAccessLists(self):
        showACL = self.interactor.runcmd('show running-config access-list', timeout=60)
        showACL = self._listFilter(showACL, r'^\s*access-list')
        aclList = []
        for acl in showACL:
            aclList.append(acl.split()[1])
        return set(aclList)

    def performUnitTests(self):
        totalTest = 0
        for aclObj in self._getUnitTestInterfaceObjects():

            numUnitTests = aclObj.numUnitTests(version=self.currentVersion)
            totalTest += numUnitTests

        print "Total Unit Tests needing to be performed: {}".format(totalTest)

        pString = "processed {:}:{:}/{:} Total:{:}/{:} Ave UT:{:3.0f}ms ETF:{}"

        tEstimator = TimeEstimator(totalTest)

        t = 0
        for aclObj in self._getUnitTestInterfaceObjects():
            unitTestGenerator = aclObj.unitTests(version=self.currentVersion)
            testResponse = aclObj.setTestResults(version=self.currentVersion)
            testResponse.next()
            numUnitTests = aclObj.numUnitTests(version=self.currentVersion)

            i = 0
            for test in unitTestGenerator:
                time1 = time.time()
                r, execMs = self.interactor.runcmd(test, returnList=False,
                                           returnTime=True)
                testResponse.send(r)
                time2 = time.time()
                tEstimator.timeRecord((time2-time1)*1000.0)
                i += 1
                t += 1
                if i % 10 == 0:
                    print pString.format(aclObj['name'], i, numUnitTests,
                                        t, totalTest,
                                        tEstimator.getRunningAverage(),
                                         tEstimator.getEstimatedFinishTime())

    def getUnitTestReports(self):
        iMappings = self.config['interfaceMappings']
        interfaces = iMappings.keys()
        if hasattr(self, 'iOverride'):
            interfaces = self.iOverride

        baselineVersion = self.config.get('baselineVersion')
        reports = ['"Baseline Version","{}"'.format(baselineVersion)]

        titleString = '"Interface","Test","ACL","Unit Test"'
        testHeaders = TestResult().getReportHeaders()

        for version in self.config['osVersions']:
            s = ''
            for h in testHeaders:
                s = s + ',"{} {}"'.format(version, h)
            titleString = titleString + s
            if baselineVersion != version:
                    titleString = titleString + ',"Behaviour {}/{}"'.format(baselineVersion,version)

        reports.append(titleString)

        for interface in interfaces:
            if 'aclObj' not in iMappings[interface].keys():
                continue

            aclObj = iMappings[interface]['aclObj']

            #print "Unit Test Report for {}".format(interface)
            reports.append(aclObj.getTestReport(self.config['osVersions'],
                                                baselineVersion))

        return '\n'.join(reports)

    def _getUnitTestInterfaceNames(self):
        iMappings = self.config['interfaceMappings']
        if hasattr(self, 'iOverride'):
            interfaces = self.iOverride
        else:
            interfaces = iMappings.keys()

        ifaceNameList = [iMappings[i]['aclObj'] for i in interfaces
                         if 'aclObj' in iMappings[i].keys()]
        return ifaceNameList

    def _getUnitTestInterfaceObjects(self):
        iMappings = self.config['interfaceMappings']
        if hasattr(self, 'iOverride'):
            interfaces = self.iOverride
        else:
            interfaces = iMappings.keys()

        ifaceObjList = [iMappings[i]['aclObj'] for i in interfaces
                if 'aclObj' in iMappings[i].keys()]
        return ifaceObjList

    def getACLEgressInterfaces(self, aclName):
        r = self.config['routeTable']
        iList = []
        if aclName in self.config['accessLists'].keys():
            aclObj = self.config['accessLists'][aclName]
            iList.append(aclObj.getDestinationInterfaces(r))

        return iList[0]

    def updateNAT(self):

        if len(self.config['nat'].keys()) > 0:
            print 'Using Cached NAT information'
            return

        natObj = Nat()
        self._updateGlobals(natObj)
        self._updateDynamicNat(natObj)
        self._updateStaticNat(natObj)

    def _updateGlobals(self, natObj):
        # Global Nat
        regex = re.compile(r'global\s+\(([^\)]+)\)\s+(\d+)\s+(.*)')
        showGlobal = self.interactor.runcmd('show running-config global', timeout=60)
        showGlobal = self._listFilter(showGlobal, r'^global')
        for line in showGlobal:
            details = {}
            m = regex.match(line)
            details.update({'interface': m.group(1)})
            details.update({'id': m.group(2)})
            details.update({'statement': m.group(3)})
            natObj.addGlobal(**details)

    def _updateDynamicNat(self, natObj):
        accessLists = self.config['accessLists']
        # Dynamic Nat
        regex = re.compile(r'nat\s+\(([^\)]+)\)\s+(\d+)\s+(.*)')
        showNat = self.interactor.runcmd('show running-config nat', timeout=60)
        showNat = self._listFilter(showNat, r'^nat')
        for line in showNat:
            details = {}
            m = regex.match(line)
            details.update({'interface': m.group(1)})
            details.update({'id': m.group(2)})
            statement = m.group(3)
            details.update({'statement': statement})
            if 'access-list' in statement:
                aclName = statement.split()[1]
                aclObj = accessLists[aclName]
                details.update({'aclObj': aclObj})

            natObj.addDynamic(**details)

    def _updateStaticNat(self, natObj):
        accessLists = self.config['accessLists']
        # Static Nat
        regex = re.compile(r'static\s+\(([^,]+),([^\)]+)\)\s+(.*)')
        showStatic = self.interactor.runcmd('show running-config static', timeout=60)
        showStatic = self._listFilter(showStatic, r'^static')
        for line in showStatic:
            details = {}
            m = regex.match(line)
            details.update({'realifc': m.group(1)})
            details.update({'mappedifc': m.group(2)})
            statement = m.group(3)
            details.update({'statement': statement})
            if 'access-list' in statement:
                i = statement.split().index('access-list')
                aclName = statement.split()[i+1]
                aclObj = accessLists[aclName]
                details.update({'aclObj': aclObj})

            natObj.addStatic(**details)

        self.config['nat'] = natObj

    def processNat(self):
        natObj = self.config['nat']
        objGrpObj = self.config['objectGroups']

        for n in natObj['dynamic']:
            if 'aclObj' in n.keys():
                self._processPolicySNAT(n)
            else:
                self._processSNAT(n)

        # If you are natting to the same IP, new syle does this by default.
        # Filter such incidents
        #useFullNat = [n for n in natObj['static']
        #              if n['mappedIp'] != n['realIP'] ]
        useFullNat = natObj['static']
        for n in useFullNat:
                if 'aclObj' in n.keys():
                    self._processPolicyStaticNAT(n)
                else:
                    self._processStaticNAT(n)

    def getNatConfig(self):
        objGrpObj = self.config['objectGroups']
        natObj = self.config['nat']

        output = [objGrpObj.getNewAndMigratedObjects(),
                  natObj.getStaticNATConfig(),
                  natObj.getPolicySNATConfig(),
                  natObj.getSNATConfig()]

        return '\n'.join(output)

    def _processSNAT(self, snatObj):
        objGrpObj = self.config['objectGroups']
        natObj = self.config['nat']
        ingressInt = snatObj['interface']
        globalId = snatObj['id']
        possibleEgressInts = natObj.getGlobalIntsById(globalId)
        egressInts = set(possibleEgressInts) - set(ingressInt)
        cidr = ipUtils.CIDRfromNetworkNetmask(snatObj['network'],
                                              snatObj['netmask'])
        snatObj.update({'cidr': cidr})
        for i in egressInts:
            objPrefix = "obj-{}-{}".format(ingressInt,i)
            grpName = objGrpObj.createNetworkGroup(prefix=objPrefix, **snatObj)
            g = natObj.getGlobalStatement(i, globalId)
            natObj.addSNAT(grpName, ingressInt, i, g)

    def _processStaticNAT(self, snatObj):
        objGrpObj = self.config['objectGroups']
        natObj = self.config['nat']
        netmask = snatObj['netmask']
        rip = snatObj['realIP']
        mip = snatObj['mappedIp']

        rcidr = ipUtils.CIDRfromNetworkNetmask(rip,
                                               netmask)
        mcidr = ipUtils.CIDRfromNetworkNetmask(mip,
                                               netmask)
        rGrp = objGrpObj.createNetworkGroup(cidr=rcidr, network=rip,
                                            netmask=netmask)
        mGrp = objGrpObj.createNetworkGroup(cidr=mcidr, network=mip,
                                            netmask=netmask)

        d = {'real_ifc': snatObj['realifc'], 'mapped_ifc': snatObj['mappedifc'],
             'real_ip': rGrp, 'mapped_ip': mGrp}
        if 'protocol' in snatObj.keys():
            realSvc = {'protocol': snatObj['protocol'],
                       'startPort': snatObj['realPort'],
                       'operator': 'eq'}

            mappedSvc = {'protocol': snatObj['protocol'],
                       'startPort': snatObj['mappedPort'],
                       'operator': 'eq'}
            realSvcGrp = objGrpObj.createServiceGroup(**realSvc)
            mappedSvcGrp = objGrpObj.createServiceGroup(**mappedSvc)
            d.update({'real_svc': realSvcGrp,
                      'mapped_svc': mappedSvcGrp})
        natObj.addStaticNAT(**d)
        # Hook into Access Lists to update to reflect new destination
        ACL = self.config['interfaceMappings'][snatObj['mappedifc']]['aclObj']
        ACL.changeDestinationIP(mcidr, rcidr)


    def _processPolicyStaticNAT(self, snatObj):
        objGrpObj = self.config['objectGroups']
        natObj = self.config['nat']
        # From what I have seen, this is pretty much static source NAT
        aclObj = snatObj['aclObj']
        real_ifc = snatObj['realifc']
        mapped_ifc = snatObj['mappedifc']
        mappedIp = snatObj['mappedIp']
        # No netmask, is it assumed /32
        if 'netmask'  in snatObj.keys():
            netmask = snatObj['netmask']
        else:
            netmask = "255.255.255.255"
        cidr = ipUtils.CIDRfromNetworkNetmask(mappedIp, netmask)
        srcIPMapped =  objGrpObj.createNetworkGroup(network=mappedIp,
                                                    netmask=netmask, cidr=cidr)
        for acl in aclObj.getTopLevelACLs():
            ACEdetails = acl.getACEDetails()
            srcIPReal, srcSvc = self._processPolicySNATSrcDst(ACEdetails['source'],
                                                      ACEdetails['protocol'])
            dstIPReal, dstSvc = self._processPolicySNATSrcDst(ACEdetails['destination'],
                                                      ACEdetails['protocol'])

            d = {'type': 'static',
                     'real_ifc': real_ifc, 'mapped_ifc': mapped_ifc,
                     'real_src': srcIPReal, 'mapped_src': srcIPMapped,
                     'real_dst': dstIPReal, 'mapped_dst': dstIPReal,
                     'srcSvc': dstSvc, 'dstSvc':dstSvc}
            natObj.addPolicySNAT(d)
            del srcIPReal, srcSvc, dstIPReal, dstSvc

    def _processPolicySNAT(self, snatObj):
        natObj = self.config['nat']
        r = self.config['routeTable']
        ingressInt = snatObj['interface']
        aclObj = snatObj['aclObj']
        globalId = snatObj['id']
        if globalId == '0':
            # Potentially NAT 0 is not needed in new world
            possibleEgressInts = r.getAllInterfaces()
            NATType = 'static'
        else:
            possibleEgressInts = natObj.getGlobalIntsById(globalId)
            NATType = 'dynamic'
        egressInts = aclObj.getDestinationInterfaces(r)

        for acl, egressInts in aclObj.getTopLevelACLs(getInterfaces=True,
                                                       routeTableObj=r):
            egressInts = egressInts - set([ingressInt])
            egressInts = egressInts & possibleEgressInts
            ACEdetails = acl.getACEDetails()
            srcIPReal, srcSvc = self._processPolicySNATSrcDst(ACEdetails['source'],
                                                      ACEdetails['protocol'])
            dstIPReal, dstSvc = self._processPolicySNATSrcDst(ACEdetails['destination'],
                                                      ACEdetails['protocol'])

            for inter in egressInts:
                if globalId == '0':
                    srcIPMapped = srcIPReal
                else:
                    g = natObj.getGlobalStatement(inter, globalId)
                    srcIPMapped = self._processSNATGlobal(g)
                d = {'type': NATType,
                     'real_ifc': ingressInt, 'mapped_ifc': inter,
                     'real_src': srcIPReal, 'mapped_src': srcIPMapped,
                     'real_dst': dstIPReal, 'mapped_dst': dstIPReal,
                     'srcSvc': dstSvc, 'dstSvc':dstSvc}
                natObj.addPolicySNAT(d)
            del srcIPReal, srcSvc, dstIPReal, dstSvc


    def _processPolicySNATSrcDst(self, sd, prot):
        objGrpObj = self.config['objectGroups']
        if 'network-object' in sd.keys():
            address = sd['network-object']
        elif 'cidr' in sd.keys():
            address = objGrpObj.createNetworkGroup(**sd)

        if prot['protocol'] == 'ip':
            service = None
        elif  'service-object' in sd.keys():
            protocolHint = prot['protocol']
            objectName = sd.get('service-object')
            service = objGrpObj.migrateToTypeObject(objectName,protocolHint)
        elif prot['protocol'] in ['tcp', 'udp'] and 'operator' in sd.keys():
            kwargs = {'protocol': prot['protocol'],
                      'operator': sd['operator'],
                      'startPort': sd['portStart']}
            if 'endport' in sd.keys():
                kwargs.update({'endPort': sd['portEnd']})
            service = objGrpObj.createServiceGroup(**kwargs)
        elif prot['protocol'] not in ['tcp', 'udp']:
            service = None
        else:
            service = None

        return address, service

    def getUpdatedACLs(self):
        accessLists = self.config['accessLists']
        #exactMatchedACLs = self.get('exactMatchedACLs')
        #netMatchedACLs = self.get('netMatchedACLs')
        aclUpdates = []
        for acl in accessLists:
            aclUpdates.append(accessLists[acl].getUpdatedACLs())

        return '\n'.join(aclUpdates)

    def _processSNATGlobal(self, d):
        objGrpObj = self.config['objectGroups']
        if 'interface' in d.keys():
            return 'interface'
        else:
            cidr = ipUtils.CIDRfromNetworkNetmask(d['network'], d['netmask'])
            d.update({'cidr': cidr})
            return objGrpObj.createNetworkGroup(**d)

    def exportRawResults(self, reportObj):
        iMappings = self.config['interfaceMappings']
        interfaces = iMappings.keys()
        if hasattr(self, 'iOverride'):
            interfaces = self.iOverride

        for interface in interfaces:
            if 'aclObj' not in iMappings[interface].keys():
                continue

            aclObj = iMappings[interface]['aclObj']

            for aclKey, version ,result in aclObj.rawTestResults():
                if isinstance(aclKey, float):
                    aclKey = "{:.3f}".format(aclKey)
                else:
                    aclKey = "{}".format(aclKey)

                reportObj.writeACLRawResults(aclObj['name'], aclKey, version,
                                            result)

    def test(self):
        accessLists = self.config['accessLists']
        r = self.config['routeTable']
        print accessLists['HPOO_NAT'].getDestinationInterfaces(r)

    def pp(self, a):
        import pprint
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(a)

from datetime import datetime, timedelta
class TimeEstimator():
    def __init__ (self, totalIterations=None):
        self.totalIterations = totalIterations
        self.currentIteration = 0
        self.runningSum = 0

    def timeRecord(self, t):
        self.currentIteration += 1
        self.runningSum += t

    def getRunningAverage(self):
        try:
            return self.runningSum / self.currentIteration
        except:
            return 0

    def getEstimatedFinishTime(self):
        if self.totalIterations > 0 and \
                    self.totalIterations > self.currentIteration:

            iterRemaining = self.totalIterations - self.currentIteration
            timeOffset = self.getRunningAverage() * iterRemaining
            finishTime = datetime.now() + timedelta(milliseconds=timeOffset)
            return finishTime.strftime('%d %b, %H:%M:%S')
        else:
            return datetime.now().strftime('%d %b, %H:%M:%S')





