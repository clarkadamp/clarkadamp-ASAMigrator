import pexpect

import getpass
import pxssh
import re
import sys
import time

class ASAInteractor (object):

    logfile = sys.stdout
    logfile = None
    prompts = []

    def __init__(self, hostname, username, password, prompt):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.prompts.append(prompt + '>')
        self.prompts.append(prompt + '#')



    def _connect(self):
        try:
            self.s =  pxssh.pxssh(timeout=5,logfile=self.logfile)
            self.s.PROMPT = 'prompt' + '>'
            self.s.login(self.hostname, self.username, self.password,
                         quiet=False, auto_prompt_reset=False,)
            self.s.sendline('login')
            self.s.expect('sername:')
            self.s.sendline(self.username)
            self.s.expect('assword:')
            self.s.sendline(self.password)
            self.s.expect(self.prompts)
            self.s.sendline('terminal pager 0')
            self.s.expect(self.prompts)
            return True
        except pxssh.ExceptionPxssh as e:
            print("pxssh failed on login.")
            print(e)
            return False

    def __enter__(self):
        OK = self._connect()
        if OK:
            return self
        else:
            return None

    def __exit__(self, type, value, traceback):
        self.s.logout()

    def runcmd(self, cmd, prompt=None, timeout=-1, returnList=True, returnTime=False):
        if prompt is None:
            prompt = self.prompts
        time1 = time.time()
        numTries = 0
        cmdExecSuccess = False
        while numTries <= 3:
            try:
                #print "executing {}".format(cmd)
                self.s.sendline(cmd)
                self.s.expect(prompt, timeout=timeout)
                cmdExecSuccess = True
                break
            except pexpect.TIMEOUT:
                numTries += 1
                print "Reconnecting: {}/{} attempts".format(numTries, 3)
                self._connect()
        if not cmdExecSuccess:
            raise pexpect.TIMEOUT
        time2 = time.time()
        execMs = (time2-time1)*1000.0
        if returnList:
            returnObj = self.s.before.split('\r\n')[1:]
        else:
            returnObj = '\n'.join(self.s.before.split('\r\n')[1:])

        if returnTime:
            return returnObj, execMs
        else:
            return returnObj




