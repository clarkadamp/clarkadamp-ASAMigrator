import re

class Nat(dict):

    def addGlobal(self, **kwargs):
        if 'global' not in self.keys():
            self.update({'global': {}})
        globalObj = self.get('global')

        details = {}
        globalId = kwargs.get('id')
        interface = kwargs.get('interface')
        if interface not in globalObj.keys():
            globalObj.update({interface: {}})

        intObj = globalObj.get(interface)
        if 'interface' in kwargs.get('statement'):
            details.update({'interface': True})
        else:
            parts = kwargs.get('statement').split()
            details.update({'network': parts[0]})
            details.update({'netmask': parts[2]})

        intObj.update({globalId: details})


    def addDynamic(self, **kwargs):
        if 'dynamic' not in self.keys():
            self.update({'dynamic': []})
        dynObj = self.get('dynamic')

        details = {}
        for k in kwargs:
            details.update({k: kwargs[k]})

        if 'aclObj' not in kwargs.keys():
            network = kwargs['statement'].split()[0]
            netmask = kwargs['statement'].split()[1]
            details.update({'network': network})
            details.update({'netmask': netmask})

        dynObj.append(details)


    def addStatic(self, **kwargs):
        if 'static' not in self.keys():
            self.update({'static': []})
        sObj = self.get('static')

        details = {}
        for k in kwargs:
            details.update({k: kwargs[k]})

        if kwargs['statement'].split()[0] in ['tcp', 'udp']:
            details = self._processStaticPAT(details, kwargs['statement'])
        else:
            details = self._processStaticNAT(details, kwargs['statement'])

        sObj.append(details)

    def _processStaticPAT(self, details, statement):
        parts = statement.split()
        details.update({'protocol': parts.pop(0)})
        if 'interface' in parts[0]:
            details.update({'mappedIp': 'interface'})
        else:
            details.update({'mappedIp': parts.pop(0)})
        details.update({'mappedPort': parts.pop(0)})
        if 'access-list' in parts[0]:
            details.update({'realIP': 'access-list'})
        else:
            details.update({'realIP': parts.pop(0)})
            details.update({'realPort': parts.pop(0)})

        validOptions = ['dns','netmask','norandomseq', 'tcp', 'udp']

        while len(parts) > 0:
            part = parts.pop(0)
            if part in ['netmask']:
                details.update({'netmask': parts.pop(0)})
            if part in ['dns', 'norandomseq']:
                details.update({part: True})
            if part in ['tcp', 'udp']:
                param = { 'maxconn': parts.pop(0) }
                if len(parts) > 0 and parts[0] not in validOptions:
                    param.update({'maxclientconn': parts.pop(0)})
                details.update({part: param})
            if part.isdigit() and int(part) < 65535:
                param = { 'maxconn': part}
                if len(parts) > 0 and parts[0] not in validOptions:
                    param.update({'maxclientconn': parts.pop(0)})
                details.update({'tcp': param})

        return details

    def _processStaticNAT(self, details, statement):
        parts = statement.split()
        if 'interface' in parts[0]:
            details.update({'mappedIp': 'interface'})
        else:
            details.update({'mappedIp': parts.pop(0)})
        if 'access-list' in parts[0]:
            details.update({'realIP': 'access-list'})
        else:
            details.update({'realIP': parts.pop(0)})

        while len(parts) > 0:
            part = parts.pop(0)
            if part in ['netmask']:
                details.update({'netmask': parts.pop(0)})
            if part in ['dns', 'norandomseq']:
                details.update({part: True})
            if part in ['tcp', 'udp']:
                param = { 'maxconn': parts.pop(0) }
                if len(parts) > 0 and parts[0].isint():
                    param.update({'maxclientconn': parts.pop(0)})
                details.update({part: param})
            if part.isdigit() and int(part) < 65535:
                param = { 'maxconn': part}
                if len(parts) > 0 and parts[0].isint():
                    param.update({'maxclientconn': parts.pop(0)})
                details.update({'tcp': param})

        return details

    def getGlobalStatement(self, interface, globalId):
        globalObj = self.get('global')
        if interface in globalObj.keys() and \
            globalId in globalObj.get(interface).keys():
                return globalObj.get(interface).get(globalId)

    def getGlobalIntsById(self, id):
        globalObj = self.get('global')
        return set([i for i in globalObj.keys() if id in globalObj[i].keys()])
    '''
    def NetworkObject(self, d, prefix='obj'):
        if 'netObj' not in self.keys():
            self.update({'netObj': {}})
        netObj = self.get('netObj')

        objectName = prefix + '-' + re.sub(r'/', '-', d['cidr'])
        if 'host' in d.keys():
            string = 'host {}'.format(d['network'])
        else:
            string = 'subnet {} {}'.format(d['network'],d['netmask'])
        if objectName not in netObj.keys():
            netObj.update({objectName: string})

        return objectName


    def getNetworkObjectConfig(self):
        netObj = self.get('netObj')
        string = 'object network {}\n {}'
        retList = []
        for k in netObj:
            retList.append(string.format(k,netObj.get(k)))
        return '\n'.join(retList)
'''
    def addPolicySNAT(self, d):
        if 'polcySNAT' not in self.keys():
            self.update({'polcySNAT': []})
        self.get('polcySNAT').append(d)

    def getPolicySNATConfig(self):
        string = 'nat ({},{}) after-auto source {} {} {} destination static {} {}'
        retList = []
        for p in self.get('polcySNAT'):
            s = string.format(p['real_ifc'], p['mapped_ifc'],
                                         p['type'],
                                         p['real_src'], p['mapped_src'],
                                         p['real_dst'], p['mapped_dst'])
            if p['dstSvc'] is not None:
                s = s + " {} {}".format(p['dstSvc'], p['dstSvc'])
            retList.append(s)
        return '\n'.join(retList)

    def addSNAT(self, grpName, real_ifc, mapped_ifc, mappedAddressInfo):
        if 'SNAT' not in self.keys():
            self.update({'SNAT': {}})
        if grpName not in self.get('SNAT').keys():
            self.get('SNAT').update({grpName: []})
        snatObj = self.get('SNAT')[grpName]
        if 'interface' in mappedAddressInfo.keys():
            address = 'interface'
        else:
            address = mappedAddressInfo['network']

        newEntry = {'real_ifc': real_ifc, 'mapped_ifc': mapped_ifc,
                    'address': address}
        # check for duplicates
        for obj in snatObj:
            if len(set(obj.items()) & set(newEntry.items())) >= \
                    len(obj.items()):
                #duplicate found
                return

        snatObj.append(newEntry)

    def getSNATConfig(self):
        natstring = ' nat ({},{}) dynamic {}'
        if 'SNAT' not in self.keys():
            return ""
        snatObj = self.get('SNAT')
        retList = []
        for k in snatObj.keys():
            retList.append('object network {}'.format(k))
            for obj in snatObj[k]:
                retList.append(natstring.format(obj['real_ifc'],
                                               obj['mapped_ifc'],
                                               obj['address']))
        return '\n'.join(retList)

    def addStaticNAT(self, **newEntry):
        if 'StaticNAT' not in self.keys():
            self.update({'StaticNAT': []})
        snatObj = self.get('StaticNAT')

        # check for duplicates
        for obj in snatObj:
            if len(set(obj.items()) & set(newEntry.items())) >= \
                    len(obj.items()):
                #duplicate found
                return
        snatObj.append(newEntry)

    def getStaticNATConfig(self):
        if 'StaticNAT' not in self.keys():
            return
        snatObj = self.get('StaticNAT')

        main = "nat ({},{}) after-auto source static {} {}"
        service = " service {} {}"

        retList = []
        for obj in snatObj:
            s = main.format(obj['real_ifc'], obj['mapped_ifc'],
                            obj['real_ip'], obj['mapped_ip'])
            if 'real_svc' in obj.keys():
                s = s + service.format(obj['real_svc'], obj['mapped_svc'])
            retList.append(s)
        return '\n'.join(retList)

    def __str__(self):

        rlist = []

        if 'global' in self.keys():
            string = "global ({}) {} {}"
            globalObj = self.get('global')
            for intKey in globalObj.keys():
                intObj = globalObj.get(intKey)
                for idKey in intObj.keys():
                    if 'interface' in intObj[idKey].keys():
                        statement = 'interface'
                    else:
                        network = intObj[idKey]['network']
                        netmask = intObj[idKey]['netmask']
                        statement = "{} netmask {}".format(network, netmask)

                    rlist.append(string.format(intKey, idKey, statement))

        if 'dynamic' in self.keys():
            string = "nat ({}) {} {}"
            dynObj = self.get('dynamic')
            for l in dynObj:
                rlist.append(string.format(l['interface'], l['id'],
                                           l['statement']))

        if 'static' in self.keys():
            print self.get('static')

        return '\n'.join(rlist)


