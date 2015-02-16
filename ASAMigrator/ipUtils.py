'''
Created on 15 Aug 2014

@author: aclark
'''
import random
import re
import struct
import socket

def randomFromCIDRAddress(cidr):
    network, prefixLen = cidr.split('/')
    if prefixLen in ['31', '32']:
        return network
    else:
        network, prefixLen = cidr.split('/')
        nwInt = aton(network)
        maxOffset = 2 ** (32 - int(prefixLen)) - 2
        if maxOffset > int(0xDFFFFFFF):
            # Make sure it is not past class C boundaries
            maxOffset = int(0xDFFFFFFF)
        randomIP = nwInt + random.randint(1, maxOffset)
        return ntoa(randomIP)

def isIPAddress(s):
    if re.search('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s):
        return True
    else:
        return False

def aton(ip):
    return struct.unpack('!I', socket.inet_aton(ip))[0]

def ntoa(i):
    return socket.inet_ntoa(struct.pack('!I', i))

def CIDRfromNetworkNetmask(network, netmask):
    return network + "/" + str(prefixLenFromNetmask(netmask))

def prefixLenFromNetmask(netmask):
    return bin(aton(netmask)).count('1')

def netmaskFromPrefixLength(length):
    bits = 0
    for i in xrange(32-int(length),32):
        bits |= (1 << i)
    return ntoa(bits)

def ipInCIDR(ip, cidr):
    ipInt = aton(ip)
    network, prefixLen = cidr.split('/')
    netInt = aton(network)
    maskInt=aton(netmaskFromPrefixLength(prefixLen))
    if ipInt & maskInt == netInt:
        return True
    else:
        return False

def CIDRMatch(cidr1, cidr2):
    c1network, c1prefixLen = cidr1.split('/')
    c2network, c2prefixLen = cidr2.split('/')
    if c1prefixLen == c2prefixLen and c1network == c2network:
        return 'exact'

    if int(c1prefixLen) > int(c2prefixLen):
        if ipInCIDR(c1network, cidr2):
            return 'subnet'
    else:
        if ipInCIDR(c2network, cidr1):
            return 'supernet'

    return False
    
    

