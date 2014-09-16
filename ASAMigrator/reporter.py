'''
Created on 1 Sep 2014

@author: adam.clark
'''
import os
import re
class reporter():

    def __init__(self, d=None):
        self.tld = d

    def writeReport(self, contents, name='report.csv'):
        filepath = '/'.join([self.tld, name])
        self.writeToFile(filepath, contents)

    def writeACLRawResults(self, aclName, index, version, contents):
        filepath = '/'.join([self.tld, aclName, index, version + '.txt'])
        self.writeToFile(filepath, re.sub(r'\n', r'\r\n', contents))

    def writeToFile(self, filepath, contents):
        if '/' in filepath:
            d = '/'.join(filepath.split('/')[0:-1])
            if not os.path.exists(d):
                os.makedirs(d)

        f = open(filepath, 'w')
        f.write(contents)
        f.close

