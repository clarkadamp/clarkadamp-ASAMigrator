import re
import ipUtils

class RouteTable(list):
    '''
    classdocs
    '''
    def __init__(self, showRouteFile=None, showRouteList=None):
        '''
        Takes argument of file that contains ASA output from the following:
        term len 0
        show route
        '''
        rawData = []
        if showRouteFile is not None:
            f = open(showRouteFile)

            try:
                for line in f:
                    cleanedLine = line.rstrip()
                    rawData.append(cleanedLine)
            except Exception, e:
                print Exception, e
        elif showRouteList is not None:
            rawData = showRouteList

        regex = re.compile(r'(via)|(directly)')
        validConfig = [line for line in rawData if regex.search(line)]
        for config in validConfig:
            parts = config.split()
            cidr = ipUtils.CIDRfromNetworkNetmask(parts[1], parts[2])
            data = {'cidr': cidr}
            data.update({'protocol': re.sub(r'\*', '', parts[0])})
            data.update({'network': parts[1]})
            data.update({'netmask': parts[2]})
            data.update({'prefixLen': ipUtils.prefixLenFromNetmask(parts[2])})
            if parts[4] == "via":
                data.update({'via': re.sub(r',', '', parts[5])})
            data.update({'interface': parts[6]})
            self.append(Route(**data))

        # Sort self by prefix length desc, then ip address asc
        self.sort(key=lambda r: (-r['prefixLen'], r['nwInt']))

    def getLongestMatch(self, ip, **kwargs ):
        # Assumes route table sorted by prefix length, return first hit
        retDetails = set(['protocol', 'cidr','network','netmask', 'interface',
                          'via'])
        for r in self:
            if r.matches(ip):
                if 'attr' in kwargs and kwargs['attr'] in r.keys():
                    return r[kwargs['attr']]
                else:
                    returnDict = {}
                    for key in set(r.keys()) & retDetails:
                        returnDict.update({key: r.get(key)})
                    return returnDict
        # Otherwise return None
        return None

    def getInterface(self, ip):
        return self.getLongestMatch(ip, attr='interface')

    def getCIDRbyInterface(self, interface):
        return [r['cidr'] for r in self if r['interface'] == interface]

    def getAllInterfaces(self):
        return set([r['interface'] for r in self])

class Route(dict):
    '''
    Individual route entry.
    '''
    def __init__(self, **kwargs):
        for k, v in kwargs.iteritems():
            self.update({k: v})

        self.update({'nwInt': ipUtils.aton(self['network'])})
        self.update({'maskInt': ipUtils.aton(self['netmask'])})

        if self.get('cidr')  == "0.0.0.0/0":
            self.update({'_default': True})

    def matches(self, ip):
        ipInt = ipUtils.aton(ip)
        if '_default' in self.keys():
            return True
        elif ipInt & self.get('maskInt') == self.get('nwInt'):
            return True
        else:
            return False

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        if 'via' in self.keys():
            return 'route {} {} {} {}'.format(self.get('interface'),
                                              self.get('network'),
                                              self.get('netmask'),
                                              self.get('via'))
        else:
            return '!{} is directly connected on {}'.format(self.get('cidr'),
                                                            self.get('interface'))
