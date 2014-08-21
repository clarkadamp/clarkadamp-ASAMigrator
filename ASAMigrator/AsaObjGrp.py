import re
import ASAInfo

class AsaObjGrp(dict):

    def __init__(self, cList):
        blkIndexes = [i for i, line in
               enumerate(cList) if line.startswith('object-group')]

        self.update({'objGrpOrder': []})
        self.update({'objGrpByName': {}})

        for index in blkIndexes:
            configBlock = ASAInfo.getRawConfigBlockFromIndex(cList, index=index)
            objGroup = ObjectGroup(configBlock)
            self.get('objGrpOrder').append(objGroup)
            self.get('objGrpByName').update({ objGroup['name']: objGroup})

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

    def __init__(self, configBlock):

        m = self.objGrpRegex.match(configBlock[0])
        grpType = m.group(1)
        grpName = m.group(2)
        grpProto = m.group(3)

        self.update({'name': grpName})
        self.update({'type': grpType})
        self.update({'protocol': grpProto})

        elements = []
        for line in configBlock[1:]:
            elements.append(objElement(line))

        self.update({'elements':  elements})

    def __str__ (self):
        return '\n'.join(self.configList())

    def configList(self):

        objHeader = "object-group {} {}".format(
                        self.get('type'), self.get('name'))
        if self.get('protocol') != None:
            objHeader = objHeader + " {}".format(self.get('protocol'))

        objConfig = [ objHeader ]
        for element in self.get('elements'):
            objConfig.append( "{}".format(element))

        return objConfig

class objElement(dict):
    def __init__ (self, line):
        '''
        self.update({'type': grpType})

        validTypes = ['description', 'group-object']
        if grpType == 'protocol':
            validTypes.append('protocol-object')
        if grpType == 'network':
            validTypes.append('network-object')
        if grpType == 'icmp-type':
            validTypes.append('icmp-object')
        if grpType == 'service':
            validTypes.append('port-object')
        '''
        lineParts = line.split()

        self.update({'elementType': lineParts[0]})
        if self.get('elementType') == 'network-object':
            '''
            network-object host host_addr | host_name
            network-object net_addr netmask
            '''
            if lineParts[1] == 'host':
                self.update({'type': 'host'})
                self.update({'network': lineParts[2]})
                self.update({'netmask': '255.255.255.255'})
            else:
                self.update({'type': 'network'})
                self.update({'network': lineParts[1]})
                self.update({'netmask': lineParts[2]})
        elif self.get('elementType') == 'port-object':
            '''
            port-object eq service
            port-object range begin_service end_service
            '''
            if lineParts[1] == 'range':
                self.update({'type': 'range'})
                self.update({'start': lineParts[2]})
                self.update({'end': lineParts[3]})
            else:
                self.update({'type': 'eq'})
                self.update({'start': lineParts[2]})
        elif self.get('elementType') == 'service-object':
            '''
            service-object [tcp|udp|tcp-udp] [eq port]
            service-object [tcp|udp|tcp-udp] [range start end]
            service-object icmp [code]
            service-object protocol
            '''
            self.update({'type': None})
            if lineParts[1] in ['tcp', 'udp','tcp-udp']:
                self.update({'protocol': lineParts[1]})

                if len(lineParts) > 2:
                    if lineParts[2] == 'range':
                        self.update({'type': 'range'})
                        self.update({'start': lineParts[3]})
                        self.update({'end': lineParts[4]})
                    else:
                        self.update({'type': 'eq'})
                        self.update({'start': lineParts[3]})
            elif lineParts[1] in ['icmp']:
                self.update({'protocol': lineParts[1]})
                if len(lineParts) > 2:
                    self.update({'type': 'icmpType'})
                    self.update({'icmpType': lineParts[2]})
            else:
                self.update({'protocol': lineParts[1]})
        elif self.get('elementType') == 'protocol-object':
            '''
            protocol-object protocol
            '''
            self.update({'protocol': lineParts[1]})
        elif self.get('elementType') == 'icmp-object':
            '''
            icmp-object icmp_type
            '''
            self.update({'icmptype': lineParts[1]})
        elif self.get('elementType') == 'group-object':
            '''
            group-object obj_grp_id
            '''
            self.update({'objGroup': lineParts[1]})
        elif self.get('elementType') == 'description':
            '''
            description text
            '''
            self.update({'description': ' '.join(lineParts[1:])})
        else:
            raise UnknownElement(self.elementType)

    def __str__ (self):
        if self.get('elementType') == 'network-object':
            if self.get('type') == 'host':
                return " {} host {}".format(self.get('elementType'),
                                            self.get('network'))
            else:
                return " {} {} {}".format(self.get('elementType'),
                                          self.get('network'),
                                        self.get('netmask'))
        elif self.get('elementType') == 'port-object':
            if self.get('type') == 'eq':
                return " {} eq {}".format(self.get('elementType'),
                                          self.get('start'))
            else:
                return " {} range {} {}".format(self.get('elementType'),
                                                self.get('start'),
                                                self.get('end'))
        elif self.get('elementType') == 'service-object':
            if self.get('protocol') in ['tcp', 'udp','tcp-udp']:
                if self.get('type') == "eq":
                    return " {} {} eq {}".format(self.get('elementType'),
                                                 self.get('protocol'),
                                                 self.get('start'))
                elif self.get('type') == "range":
                    return " {} {} range {} {}".format(self.get('elementType'),
                                                       self.get('protocol'),
                                                       self.get('start'),
                                                       self.get('end'))
                else:
                    return " {} {}".format(self.get('elementType'),
                                           self.get('protocol'))

            elif self.get('protocol') in ['icmp']:
                if self.get('type') == 'icmpType':
                    return " {} {} {}".format(self.get('elementType'),
                                              self.get('protocol'),
                                              self.get('icmpType'))
                else:
                    return " {} {}".format(self.get('elementType'),
                                           self.get('protocol'))
            else:
                return " {} {}".format(self.get('elementType'),
                                       self.get('protocol'))
        elif self.get('elementType') == 'protocol-object':
            return ' {} {}'.format(self.get('elementType'),
                                   self.get('protocol'))
        elif self.get('elementType') == 'icmp-object':
            return ' {} {}'.format(self.get('elementType'),
                                   self.get('icmpType'))
        elif self.get('elementType') == 'group-object':
            return ' {} {}'.format(self.get('elementType'),
                                   self.get('objGroup'))
        elif self.get('elementType') == 'description':
            return ' {} {}'.format(self.get('elementType'),
                                   self.get('description'))

class UnknownElement(Exception):
    def __init__(self,objName):
        self.message = "{} is not a valid object-group element type".format(
                                                                    objName)
    def __str__(self):
        return repr(self.message)
