#!/usr/bin/env python
# encoding: utf-8
'''
ASAMig -- shortdesc

ASAMig is a description

It defines classes_and_methods

@author:     user_name

@copyright:  2014 organization_name. All rights reserved.

@license:    license

@contact:    user_email
@deffield    updated: Updated
'''

import re
import sys
import os

from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter

from ASAMigrator.ASAInteractor import *
from ASAMigrator.ASAProcessor import *

__all__ = []
__version__ = 0.1
__date__ = '2014-08-21'
__updated__ = '2014-08-21'

DEBUG = 0
TESTRUN = 0
PROFILE = 0

class CLIError(Exception):
    '''Generic exception to raise and log different fatal errors.'''
    def __init__(self, msg):
        super(CLIError).__init__(type(self))
        self.msg = "E: %s" % msg
    def __str__(self):
        return self.msg
    def __unicode__(self):
        return self.msg

def startProcessor(ASAi=None, **kwargs):
    if kwargs['noSave'] == True:
        saveState=False
    else:
        saveState=True

    with ASAProcessor(ASAi, saveState) as ASAp:
        if kwargs['connect']:
            print ASAp.updateOsVersions(isBaseline=kwargs['gatherBaseline'])
            if kwargs['gatherBaseline']:
                ASAp.updateRouteTable()
                ASAp.updateObjectGroups()
                ASAp.updateAccessLists()
                ASAp.updateAccessGroupMappings()
                ASAp.updateNAT()
            if kwargs['unitTests']:
                ASAp.prepareUnitTests()
                ASAp.performUnitTests()
        if kwargs['report'] is not None:
            print ASAp.getUnitTestReports()


        if False:
            ASAp.processNat()
            ASAp.getNatConfig()
            ASAp.getUpdatedACLs()

        #ASAp.test()

        #print ASAp.getACLEgressInterfaces('ahm')

def main(argv=None): # IGNORE:C0111
    '''Command line options.'''

    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)

    program_name = os.path.basename(sys.argv[0])
    program_version = "v%s" % __version__
    program_build_date = str(__updated__)
    program_version_message = '%%(prog)s %s (%s)' % (program_version, program_build_date)
    program_shortdesc = __import__('__main__').__doc__.split("\n")[1]
    program_license = '''%s

  Created by user_name on %s.
  Copyright 2014 organization_name. All rights reserved.

  Licensed under the Apache License 2.0
  http://www.apache.org/licenses/LICENSE-2.0

  Distributed on an "AS IS" basis without warranties
  or conditions of any kind, either express or implied.

USAGE
''' % (program_shortdesc, str(__date__))

    try:
        # Setup argument parser
        parser = ArgumentParser(description=program_license, formatter_class=RawDescriptionHelpFormatter)


        parser.add_argument('-V', '--version', action='version', version=program_version_message)
        parser.add_argument("-v", "--verbose", dest="verbose", action="count", help="set verbosity level [default: %(default)s]")
        parser.add_argument("-b", "--baseline", dest="gatherBaseline", action="store_true", help="Gather baseline data from source ASA")
        parser.add_argument("-s", "--state", dest="stateFile", help="Set location of config state file [default: %(default)s]", metavar="FILE", default='state.pkl' )
        parser.add_argument("-n", "--no-save", dest="noSave", action="store_true", help="Don't save state upon exit")
        parser.add_argument("-i", "--ignore-state", dest="ignoreState", action="store_true", help="Ignore state information")
        parser.add_argument("-u", "--unittests", dest="unitTests", action="store_true", help="Perform ACL Unit Tests against stored state data")
        parser.add_argument("-r", "--report", dest="report", help="Location for the unit test report [default: %(default)s]", metavar="FILE")
        parser.add_argument('-P', "--prompt", dest="prompt", help="Command Line Prompt, set via hostname command [default: %(default)s]", metavar="PROMPT", default='ciscoasa')
        parser.add_argument('-c', "--connect", dest="host", help="ASA to connect to", metavar="user:password@host.name")

        # Process arguments
        args = parser.parse_args()
        kwargs = {}
        kwargs['ignoreState'] = args.ignoreState
        kwargs['noSave'] = args.noSave
        kwargs['gatherBaseline'] = args.gatherBaseline
        kwargs['unitTests'] = args.unitTests
        kwargs['report'] = args.report
        kwargs['connect'] = args.host

    except KeyboardInterrupt:
        ### handle keyboard interrupt ###
        return 0
    except Exception, e:
        if DEBUG or TESTRUN:
            raise(e)
        indent = len(program_name) * " "
        sys.stderr.write(program_name + ": " + repr(e) + "\n")
        sys.stderr.write(indent + "  for help use --help\n")
        return 2

    if args.host is not None:
        connect = True
        m = re.match(r'(.*?)(?::(.*))?@(.*)', args.host)
        username, password, hostname =  m.group(1), m.group(2), m.group(3)
    else:
        connect = False


    if connect:
        with ASAInteractor(hostname, username, password, args.prompt) as ASAi:
            startProcessor(ASAi, **kwargs)
    else:
        startProcessor(None, **kwargs)



if __name__ == "__main__":
    if DEBUG:
        sys.argv.append("-h")
        sys.argv.append("-v")
        sys.argv.append("-r")
    if TESTRUN:
        import doctest
        doctest.testmod()
    if PROFILE:
        import cProfile
        import pstats
        profile_filename = 'ASAMig_profile.txt'
        cProfile.run('main()', profile_filename)
        statsfile = open("profile_stats.txt", "wb")
        p = pstats.Stats(profile_filename, stream=statsfile)
        stats = p.strip_dirs().sort_stats('cumulative')
        stats.print_stats()
        statsfile.close()
        sys.exit(0)
    sys.exit(main())
