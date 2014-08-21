import os
import pickle
import re
import sys
import time
from AsaACL import *
from AsaNat import *
from AsaObjGrp import *
from RouteTable import *

class ASAProcessor():

    config = {'source': 'ASAProcessor'}
    config['osVersions'] = []
    config['interfaceMappings'] = {}
    config['accessLists'] = {}
    config['nat'] = {}

    stateSave = 'ASAProcessorState.pkl'
    useCache = True
    iOverride = ['ahm']


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
        print "start exit"

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

    def updateOsVersions(self):
        showVer = self.interactor.runcmd('show version')
        version = [l for l in showVer if 'Software Version' in l][0].split()[-1]
        version = re.sub(r'[()]', '', version)
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
            print self.config['objectGroups']
            return

        showObj = self.interactor.runcmd('show running-config object-group', timeout=60)
        objGrpObj = AsaObjGrp(showObj)
        self.config['objectGroups'] = objGrpObj

    def updateAccessLists(self):
        accessLists = self.config['accessLists']
        if self.useCache:
            ACLs = [a for a in self.getAccessLists()
                    if a not in accessLists.keys()]
        else:
            ACLs = self.getAccessLists()

        for ACL in ACLs:
            aclList = self.getShowAccessList(ACL)
            aclObj = AsaAcl(aclList)
            accessLists.update({ACL: aclObj})

    def updateAccessGroupMappings(self):
        accessGroupCfgLst = self.interactor.runcmd('show running-config access-group')
        accessGroupCfgLst = self._listFilter(accessGroupCfgLst, r'^access')
        agm = {}
        accessLists = self.config['accessLists']
        for item in accessGroupCfgLst:
            parts = item.split()
            ACLName = parts[1]
            interface = parts[4]
            if interface in self.config['interfaceMappings'].keys():
                pass
            else:
                agm.update({interface: {'acl': ACLName}})
                agm.update({interface: {'aclObj': accessLists[ACLName]}})
                self.config['interfaceMappings'].update(agm)

    def prepareUnitTests(self):
        if hasattr(self, 'iOverride'):
            interfaces = self.iOverride
        else:
            interfaces = self._getUnitTestInterfaceObjects()

        r = self.config['routeTable']
        for interface in interfaces:
            aclObj = self.config['accessLists'][interface]
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

        string = '"Interface","Test","ACL","Unit Test"'
        for version in self.config['osVersions']:
            string = string + ',"{} action","{} reason"'.format(version, version)

        reports = [string]
        for interface in interfaces:
            if 'aclObj' not in iMappings[interface].keys():
                continue

            aclObj = iMappings[interface]['aclObj']

            #print "Unit Test Report for {}".format(interface)
            reports.append(aclObj.getTestReport(self.config['osVersions']))

        return '\n'.join(reports)

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
        accessLists = self.config['accessLists']
        if 'nat' in self.config.keys():
            print 'Using Cached NAT information'
            return

        natObj = Nat()
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
                details.update({'aclObj': aclObj})

            natObj.addStatic(**details)

        self.config['nat'] = natObj


    def test(self):
            print self.config['nat']




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





