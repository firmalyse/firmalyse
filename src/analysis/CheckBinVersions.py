"""
Check the versions of important binaries in the firmware
"""

import subprocess

class CheckBinVersions:

    def __init__(self, firmwareFolder):
        self.firmwareFolder = firmwareFolder
        self.ssh = ''
        self.busyBox = ''
        self.telnet = ''
        self.openssl = ''

    def run(self):
        self.findFiles()

        if self.openssl != '':
            openSSLIssues = self.checkOpenSSL()

    
    def checkOpenSSL(self):
        """
        Checks if the OpenSSL version is outdated or vulnerable
        to the heartbleed attack.
        """
        
        issues = {'Heartbleed': False, 'Outdated': False}

        relativePath = 'analysis_result/' + self.firmwareFolder + '/' + self.openssl
        versionStr = subprocess.check_output('strings -n 10 ' + relativePath + '| grep \"OpenSSL\"', shell=True).split('\n')[-2]
        versionNum = versionStr.split(' ')[1]

        print(versionNum)

        # Check if the version of OpenSSL is vulnerable to the heartbleed attack
        if '1.0.1' in versionNum:
            issues['Heartbleed'] = True
        
        # Check if the version of OpenSSL is outdated (no longer supported)
        with open('analysis/data/OpenSSLOutdatedVersions', 'r') as outdatedVersions:
            for line in outdatedVersions:
                if versionNum[:-1] in line:
                    issues['Outdated'] = True
                    break

        return issues

    def findFiles(self):
        """
        Find important binary files (ssh, busy box, telnet, openssl).
        """

        with open('analysis_result/firmwalkerOutput.txt', 'r') as firmwalker:
            for line in firmwalker:
                if line.startswith('##################################### ssh'):
                    self.ssh = next(firmwalker).strip('d/').strip('\n')
                elif line.startswith('##################################### busybox'):
                    self.busyBox = next(firmwalker).strip('d/').strip('\n')
                elif line.startswith('##################################### telnet'):
                    self.telnet = next(firmwalker).strip('d/').strip('\n')
                elif line.startswith('##################################### openssl'):
                    self.openssl = next(firmwalker).strip('d/').strip('\n')
                
        # test
        print("ssh: {}".format(self.ssh))
        print("busybox: {}".format(self.busyBox))
        print("telnet: {}".format(self.telnet))
        print("openssl: {}".format(self.openssl))
