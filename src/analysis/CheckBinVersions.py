"""
Check the versions of important binaries in the firmware
"""

import subprocess

class CheckBinVersions:

    def __init__(self, firmwareFolder):
        self.firmwareFolder = firmwareFolder
        self.ssh = ''
        self.dropbear = ''
        self.busyBox = ''
        self.telnet = ''
        self.openssl = ''

    def run(self):
        self.findFiles()

        self.checkOpenSSL()
        self.checkTelnet()
        self.checkBusyBox()
        self.checkDropbear()

    
    def checkOpenSSL(self):
        """
        Checks if the OpenSSL version is outdated or vulnerable
        to the heartbleed attack.
        """
        
        issues = {'Present': False, 'Heartbleed': False, 'Outdated': False}

        if self.openssl == '': 
            return issues
        
        issues['Present'] = True

        relativePath = 'analysis_result/' + self.firmwareFolder + '/' + self.openssl
        versionStr = subprocess.check_output('strings -n 10 ' + relativePath + '| grep \"OpenSSL\"', shell=True).split('\n')[-2]
        versionNum = versionStr.split(' ')[1]

        # Check if the version of OpenSSL is vulnerable to the heartbleed attack
        if '1.0.1' in versionNum:
            issues['Heartbleed'] = True
        
        # Check if the version of OpenSSL is outdated (no longer supported)
        with open('analysis/data/OpenSSLOutdatedVersions', 'r') as outdatedVersions:
            for line in outdatedVersions:
                if versionNum[:-1] in line:
                    issues['Outdated'] = True
                    break

        # print("OpenSSL: {}".format(issues))

        return issues
    
    def checkBusyBox(self):
        """
        Checks if there is a vulnerable version of BusyBox in the firmware.
        """

        issues = {'Present': False, 'VulnerableVersion': False}

        if self.busyBox == '':
            return issues

        issues['Present'] = True

        relativePath = 'analysis_result/' + self.firmwareFolder + '/' + self.busyBox
        keywordsArray = subprocess.check_output('strings ' + relativePath + '| grep -P \"^BusyBox v([0-9])+\.([0-9])+.+\"', shell=True)\
                        .split('\n')
        keywordsArray = filter(None, keywordsArray) # Filter out empty string since subprocess.check_output throws out extra newline
        versionNum = keywordsArray[0].split(' ')[1].strip('v') # Just take the 1st result of grep as the target version string

        # print("Version caught: {}".format(versionNum))
        
        # Check if the version of BusyBox is vulnerable
        with open('analysis/data/BusyBoxVulnerableVersions', 'r') as vulnerableVersions:
            for line in vulnerableVersions:
                if versionNum in line:
                    issues['VulnerableVersion'] = True
                    break
        
        # print("BusyBox: {}".format(issues))
        
        return issues

    def checkDropbear(self):
        """
        Checks if there is a vulnerable version of Dropbear in the firmware.
        """

        issues = {'Present': False, 'VulnerableVersion': False}

        if self.dropbear == '':
            return issues
        
        issues['Present'] = True

        relativePath = 'analysis_result/' + self.firmwareFolder + '/' + self.dropbear
        keywordsArray = subprocess.check_output('strings ' + relativePath +\
                                                 '| grep -P \"^SSH-([0-9])+\.([0-9]+)-dropbear_([0-9])+\.([0-9])+\"',\
                                                 shell=True).split("\n")
        keywordsArray = filter(None, keywordsArray) # Filter out empty string since subprocess.check_output throws out extra newline
        versionNum = keywordsArray[0].split('_')[1] # Just take the 1st result of grep as the target version string

        # print("Version caught: {}".format(versionNum))

        # Check if the version of Dropbear is vulnerable
        with open('analysis/data/DropbearVulnerableVersions', 'r') as vulnerableVersions:
            for line in vulnerableVersions:
                if versionNum in line:
                    issues['VulnerableVersion'] = True
                    break
        
        # print("Dropbear: {}".format(issues))

        return issues

    def checkTelnet(self):
        """
        Checks if telnet is present in the firmware.
        Note: telnet inherently insecure (plaintext communication) and will be flagged if present.
        """

        issues = {'Present': False}

        if self.telnet != '':
            issues['Present'] = True

        # print("Telnet: {}".format(issues))

        return issues

    def findFiles(self):
        """
        Find important binary files (ssh, busy box, telnet, openssl).
        """

        with open('analysis_result/firmwalkerOutput.txt', 'r') as firmwalker:
            for line in firmwalker:
                if line.startswith('##################################### ssh'):
                    self.ssh = next(firmwalker).strip('d/').strip('\n')
                elif line.startswith('##################################### dropbear'):
                    self.dropbear = next(firmwalker).strip('d/').strip('\n')
                elif line.startswith('##################################### busybox'):
                    self.busyBox = next(firmwalker).strip('d/').strip('\n')
                elif line.startswith('##################################### telnet'):
                    self.telnet = next(firmwalker).strip('d/').strip('\n')
                elif line.startswith('##################################### openssl'):
                    self.openssl = next(firmwalker).strip('d/').strip('\n')
                
        # test
        # print("ssh: {}".format(self.ssh))
        # print("dropbear: {}".format(self.dropbear))
        # print("busybox: {}".format(self.busyBox))
        # print("telnet: {}".format(self.telnet))
        # print("openssl: {}".format(self.openssl))
