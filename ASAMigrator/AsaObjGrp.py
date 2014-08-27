import copy
import re
import ASAInfo

class AsaObjGrp(dict):

    def __init__(self):
        self.update({'objGrpOrder': []})
        self.update({'objGrpByName': {}})

    def createGroupsFromConfig(self, cList):
        blkIndexes = [i for i, line in
               enumerate(cList) if line.startswith('object-group')]

        for index in blkIndexes:
            configBlock = ASAInfo.getRawConfigBlockFromIndex(cList, index=index)
            objGroup = ObjectGroup()
            objGroup.fromConfigBlock(configBlock)
            self.get('objGrpOrder').append(objGroup)
            self.get('objGrpByName').update({ objGroup['name']: objGroup})

    def createServiceGroup(self, prefix='obj', **svc):
        svc.update({'type': 'service'})
        name = '{}-{}'.format(prefix, svc['protocol'])
        if 'operator' in svc.keys():
            name = name + '-{}-{}'.format(svc['operator'], svc['startPort'])
            if svc['operator'] == 'range':
                name = name + '-{}'.format(svc['endPort'])
        elif 'icmpCode' in svc.keys():
            name = name + '-{}'.format(svc['icmpCode'])
        if not self.isObjectGroup(name):
            d = {'name': name}
            d.update({'type': 'service'})
            d.update({'CfgType': 'obj'})
            d.update({'elements': [svc]})
            newObj = ObjectGroup()
            newObj.fromDict(d)
            self.get('objGrpOrder').append(newObj)
            self.get('objGrpByName').update({ newObj['name']: newObj})
            if 'additional' not in self.keys():
                self.update({'additional': []})
            self.get('additional').append(newObj)
        return name

    def createNetworkGroup(self, prefix='obj', **d):
        name = prefix + '-' + re.sub(r'/', '-', d['cidr'])
        nets = {'type': 'subnet'}
        if 'host' in d.keys():
            nets.update({'host': True})
            nets.update({'network': d['network']})
        else:
            nets.update({'network': d['network']})
            nets.update({'netmask': d['netmask']})

        if not self.isObjectGroup(name):
            d = {'name': name}
            d.update({'type': 'network'})
            d.update({'CfgType': 'obj'})
            d.update({'elements': [nets]})
            newObj = ObjectGroup()
            newObj.fromDict(d)
            self.get('objGrpOrder').append(newObj)
            self.get('objGrpByName').update({ newObj['name']: newObj})
            if 'additional' not in self.keys():
                self.update({'additional': []})
            self.get('additional').append(newObj)
        return name

    def getObjectGroupType(self, s):
        if self.isObjectGroup(s):
            return self.getObjectGroup(s)['type']

    def getObjectGroup(self, s):
        if self.isObjectGroup(s):
            return self.get('objGrpByName')[s]

    def isObjectGroup(self, s):
        if s in self.get('objGrpByName').keys():
            return True

    def objectGroupIsType(self, s, t):
        if self.getObjectGroup(s)['type'] == t:
            return True
        else:
            return False

    def migrateToTypeObject(self, s, protocolHint=None):
        legacyObj = self.getObjectGroup(s)
        legacyName = legacyObj.get('name')
        newName = 'mobj-' + legacyName
        if not self.isObjectGroup(newName):
            newObj = copy.deepcopy(legacyObj)
            newObj.setName(newName)
            newObj.setCfgType('obj')
            if protocolHint:
                newObj.setProtocol(protocolHint)

            self.get('objGrpOrder').append(newObj)
            self.get('objGrpByName').update({ newObj['name']: newObj})
            if 'additional' not in self.keys():
                self.update({'additional': []})
            self.get('additional').append(newObj)
        return newName

    def getNewAndMigratedObjects(self):
        rList = []
        for o in self.get('additional'):
            rList.append(o._getConfigObjectVersion())
        return '\n'.join(rList)

    def _getObjVersion(self):
        rList = []
        for o in self.get('objGrpOrder'):
            rList.append(o._getConfigObjectVersion())
        return '\n'.join(rList)

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        rList = []
        for o in self.get('objGrpOrder'):
            rList.append(str(o))
        return '\n'.join(rList)

class ObjectGroup(dict):

    '''
    Reegx to parse the following syntax:
        object-group {protocol | network | icmp-type} obj_grp_id
        object-group service obj_grp_id [tcp | udp | tcp-udp]
    '''
    objGrpRegex = re.compile(
        r'object-group\s+((?:protocol)|(?:network)|(?:icmp-type)|(?:service))\s+([\w+_\-\.]+)(?:\s+((?:tcp)|(?:udp)|(?:tcp-udp)))?$')

    def fromConfigBlock(self, configBlock, CfgType='objGrp'):
        m = self.objGrpRegex.match(configBlock[0])
        grpType, grpName, grpProto = m.groups()

        self.update({'name': grpName})
        self.update({'type': grpType})
        self.update({'CfgType': CfgType})
        if grpProto:
            self.update({'protocol': grpProto})

        handlers = {'network-object': self._handleNetworkObject,
                    'port-object': self._handlePortObject,
                    'service-object': self._handleServiceObject,
                    'protocol-object': self._handleProtocolObject,
                    'icmp-object': self._handleIcmpObject,
                    'group-object': self._handleGroupObject,
                    'description': self._handleDescription}

        elements = []
        for line in configBlock[1:]:
            itemType = line.split()[0]
            d = handlers[itemType](line.split())
            elements.append(ObjectElement(**d))

        self.update({'elements':  elements})

    def fromDict(self, d):
        self.update({'name': d['name']})
        self.update({'type': d['type']})
        self.update({'CfgType': d['CfgType']})

        elements = []
        for svc in d['elements']:
            elements.append(ObjectElement(**svc))

        self.update({'elements':  elements})

    def _handleNetworkObject(self, lineParts):
        '''
        network-object host host_addr | host_name
        network-object net_addr netmask
        '''
        d = {'type': lineParts[0]}
        if lineParts[1] == 'host':
            d.update({'host': True})
            d.update({'network': lineParts[2]})
            d.update({'netmask': '255.255.255.255'})
        else:
            d.update({'network': lineParts[1]})
            d.update({'netmask': lineParts[2]})
        return d

    def _handlePortObject(self, lineParts):
        '''
        port-object eq service
        port-object range begin_service end_service
        '''
        d = {'type': lineParts[0]}
        d.update({'operator': lineParts[1]})
        d.update({'startPort': lineParts[2]})
        if lineParts[1] == 'range':
            d.update({'endPort': lineParts[3]})
        return d

    def _handleServiceObject(self, lineParts):
        '''
        service-object [tcp|udp|tcp-udp] [eq port]
        service-object [tcp|udp|tcp-udp] [range start end]
        service-object icmp [code]
        service-object protocol
        '''
        d = {'type': lineParts[0]}
        d.update({'protocol': lineParts[1]})

        if lineParts[1] in ['tcp', 'udp','tcp-udp']:
            d.update({'operator': lineParts[2]})
            d.update({'startPort': lineParts[3]})
            if lineParts[2] == 'range':
                d.update({'endPort': lineParts[4]})
        elif lineParts[1] in ['icmp']:
            if len(lineParts) > 2:
                d.update({'icmpCode': lineParts[2]})
        return d

    def _handleProtocolObject(self, lineParts):
        '''
        protocol-object protocol
        '''
        d = {'type': lineParts[0]}
        d.update({'protocol': lineParts[1]})
        return d

    def _handleIcmpObject(self, lineParts):
        '''
        icmp-object icmp_type
        '''
        d = {'type': lineParts[0]}
        d.update({'icmpCode': lineParts[1]})
        return d

    def _handleGroupObject(self, lineParts):
        '''
        group-object obj_grp_id
        '''
        d = {'type': lineParts[0]}
        d.update({'groupName': lineParts[1]})
        return d

    def _handleDescription(self, lineParts):
        '''
        description text
        '''
        d = {'type': lineParts[0]}
        d.update({'description': " ".join(lineParts[1:])})
        return d

    def _getConfigObjectGroupVersion(self):
        header = "object-group {} {}".format(self.get('type'),
                                             self.get('name'))
        if 'protocol' in self.keys():
            header = header + " {}".format(self.get('protocol'))
        config =  [header]
        for e in self.get('elements'):
            elementString = " {}".format(e.getConfig(self, cFormat='objGrp'))
            config.append(elementString)
        return '\n'.join(config)

    def _getConfigObjectVersion(self):
        if self.get('type') in ['icmp-type', 'protocol']:
            objType = 'service'
        else:
            objType = self.get('type')
        header = "object {} {}".format(objType,
                                             self.get('name'))
        config =  [header]
        for e in self.get('elements'):
            elementString = " {}".format(e.getConfig(self, cFormat='obj'))
            config.append(elementString)
        return '\n'.join(config)

    def setProtocol(self, p):
        self.update({'protocol': p})

    def setName(self, n):
        self.update({'name': n})

    def setCfgType(self, c):
        self.update({'CfgType': c})

    def getProtocols(self):

        if self.get('type') != 'service':
            return

        if 'protocol' in self.keys():
            protocol = self.get('protocol')
        elif 'protocolHint' in self.get('protocol'):
            protocol = self.get('protocolHint')

        if protocol in ['tcp', 'udp']:
            return [protocol]
        else:
            return ['tcp', 'udp']

    def __str__ (self):
        if self.get('CfgType') == 'objGrp':
            rList = self._getConfigObjectGroupVersion()
        else:
            rList = self._getConfigObjectVersion()
        return '\n'.join(rList)


class ObjectElement(dict):
    def __init__(self, **kwargs):
        for k, v in kwargs.iteritems():
            self.update({k: v})

    def getConfig(self, parentObj, cFormat=None):
        formatters = {'objGrp': self._objGrpVersion,
                      'obj': self._objVersion}
        if cFormat in ['objGrp', 'obj']:
            return formatters[cFormat](parentObj)
        else:
            return formatters[parentObj['CfgType']](parentObj)

    def _objGrpVersion(self, parentObj):
        eType = self.get('type')
        if eType == 'network-object':
            if 'host' in self.keys():
                s = 'network-object host {}'.format(self.get('network'))
            else:
                s = 'network-object {} {}'.format(self.get('network'),
                                                  self.get('netmask'))
        elif eType == 'port-object':
            s = 'port-object {} {}'.format(self.get('operator'),
                                              self.get('startPort'))
            if self.get('operator') == 'range':
                s = s + " {}".format(self.get('endPort'))
        elif eType == 'service-object':
            if self.get('protocol') in ['tcp', 'udp', 'tcp-udp']:
                s = 'service-object {} {} {}'.format(self.get('protocol'),
                                                     self.get('operator'),
                                                     self.get('startPort'))
                if self.get('operator') == 'range':
                    s = s + " {}".format(self.get('endPort'))
            elif self.get('protocol') == 'icmp':
                s = 'service-object icmp'
                if 'icmpCode' in self.keys():
                    s = s + ' {}'.format(self.get('icmpCode'))
            else:
                s = 'service-object {}'.format(self.get('protocol'))
        elif eType in ['protocol-object', 'icmp-object', 'group-object', 'description']:
            possibleArgs = set(['protocol', 'icmpCode', 'groupName', 'description'])
            arg = list(set(self.keys()) & possibleArgs)[0]
            s = "{} {}".format(eType, self.get(arg))
        else:
            s = ''
        return s

    def _objVersion(self, parentObj):
        eType = self.get('type')
        if eType in ['network-object', 'subnet', 'host']:
            if 'host' in self.keys():
                s = 'host {}'.format(self.get('network'))
            else:
                s = 'subnet {} {}'.format(self.get('network'),
                                                  self.get('netmask'))
            return s
        elif eType == 'port-object':
            protocols = parentObj.getProtocols()
            rList = []
            for protocol in protocols:
                t = 'service {} destination {} {}'.format(protocol,
                                                          self.get('operator'),
                                                          self.get('startPort'))
                if self.get('operator') == 'range':
                    t = t + " {}".format(self.get('endPort'))
                rList.append(t)
            return '\n '.join(rList)
        elif eType in ['service-object' , 'service']:
            if self.get('protocol') in ['tcp', 'udp', 'tcp-udp']:
                s = 'service {} destination {} {}'.format(self.get('protocol'),
                                                          self.get('operator'),
                                                          self.get('startPort'))
                if self.get('operator') == 'range':
                    s = s + " {}".format(self.get('endPort'))
                return s
            elif self.get('protocol') == 'icmp' or eType == 'icmp-object':
                s = 'service icmp'
                if 'icmpCode' in self.keys():
                    s = s + ' {}'.format(self.get('icmpCode'))
                return s
            else:
                return 'service {}'.format(self.get('protocol'))
        elif eType == 'icmp-object':
            return 'service icmp {}'.format(self.get('icmpCode'))
        elif eType == 'protocol-object':
            return 'service {}'.format(self.get('protocol'))
        elif eType in ['description']:
            return "description {}".format(self.get('description'))
        elif eType in ['group-object']:
            print "Unable to convert group-object {} in object-group {}".format(self.get('groupName'), parentObj.get('name'))
        else:
            print self.copy()
            print "have no idea what to do with {}".format(eType)

class UnknownElement(Exception):
    def __init__(self,objName):
        self.message = "{} is not a valid object-group element type".format(
                                                                    objName)
    def __str__(self):
        return repr(self.message)
