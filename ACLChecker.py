import re
import pickle
import os

from ASAInteractor import *
from ASAProcessor import *

hostname = '10.122.13.69'
username = 'cisco'
password = 'cisco123'

connect = True

def startProcessor(ASAi=None):
    with ASAProcessor(ASAi, saveState=False) as ASAp:
        if connect:
            pass
            #ASAp.updateOsVersions()
            #ASAp.updateRouteTable()
            ASAp.updateObjectGroups()
            #ASAp.updateAccessLists()
            #ASAp.updateAccessGroupMappings()
            #ASAp.updateNAT()
            #ASAp.prepareUnitTests()
            #ASAp.performUnitTests()
            #print ASAp.getUnitTestReports()

        #print ASAp.test()
        #print ASAp.getACLEgressInterfaces('ahm')

if connect:
    with ASAInteractor(hostname, username, password, 'ciscoasa') as ASAi:
        startProcessor(ASAi)
else:
    startProcessor()