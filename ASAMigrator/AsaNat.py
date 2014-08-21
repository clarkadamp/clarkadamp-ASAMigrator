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
            netmask = kwargs['statement'].split()[0]
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

        validOptions = ['dns','netmask','norandomseq', 'tcp', 'udp']

        while len(parts) > 0:
            part = parts.pop(0)
            if part in ['netmask']:
                details.update({'netmask': part})
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
                details.update({'netmask': part})
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


