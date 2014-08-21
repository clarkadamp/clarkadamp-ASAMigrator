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

