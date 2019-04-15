"""
Search for hardcoded X.509 and SSH private keys
"""

import platform

class HardcodedKeys:

    def __init__(self, firmwareFolder):
        self.firmwareFolder = firmwareFolder
        self.result = {
            'name': 'Checks for hardcoded cryptographic keys in the firmware',
            'description': 'The use of hardcoded cryptographic keys are often reused by manufacturers of IoT devices. \
                            Any attacker that posseses these keys can use them to hijack the communication \
                            made by these IoT devices. These module thus scans for the presence of such hardcoded keys\
                            used as SSH host keys or X.509 HTTPS certificate',
            'issues': []
        }        

    def run(self):
        sslFilesExtracted, sshFilesExtracted = self.extractFiles()
        self.result['issues'].append(self.verifySSLKeys(sslFilesExtracted))
        self.result['issues'].append(self.verifySSHKeys(sshFilesExtracted))

    def verifySSHKeys(self, sshFiles):
        """
        Verfies if the SSH related files contain private keys
        and returns an array of such files that are true positive.
        Uses the fact that the default SSH key name is "id_rsa" or "id_dsa" where private keys
        are embded in headers containing "PRIVATE",
        and Dropbear private key file names usually contains "host_key".
        """
        
        issues = {'issueName': 'SSH private keys', 'Present': False, 'PrivateKeys': []}

        positiveFiles = []
        for filePath in sshFiles:
            if "host_key" and "dropbear" in filePath: # Dropbear
                positiveFiles.append(filePath)
            elif "id_rsa" or "id_dsa" in filePath: # SSH keys
                if ".pub" not in filePath: # Not public keys
                    try:
                        with open('analysis_result/' + self.firmwareFolder + '/' + filePath, 'r') as targetFile:
                            print("Checking {}".format(filePath))
                            if targetFile.read().find("PRIVATE") != -1:
                                positiveFiles.append(filePath)
                    except IOError:
                        continue

        if len(positiveFiles) > 0:
            issues['Present'] = True
            issues['PrivateKeys'] = list(positiveFiles)
        
        return issues

    def verifySSLKeys(self, sslFiles):
        """
        Verifies if the SSL related files contain private keys
        and returns an array of such files that are true positive.
        Uses the fact that SSL private keys are embded in between headers that contains "PRIVATE"
        """

        issues = {'issueName': 'SSL private keys', 'Present': False, 'PrivateKeys': []}

        positiveFiles = []
        for filePath in sslFiles:
            try:
                with open('analysis_result/' + self.firmwareFolder + '/' + filePath, 'r') as targetFile:
                    if targetFile.read().find("PRIVATE") != -1:
                        positiveFiles.append(filePath)
            except IOError:
                continue
        
        if len(positiveFiles) > 0:
            issues['Present'] = True
            issues['PrivateKeys'] = list(positiveFiles)
        
        return issues

    def extractFiles(self):

        # SSL and SSH files keywords from firmwalker
        with open('analysis/data/HardcodedSSLKeys.txt', 'r') as sslKeywordsFile:
            sslKeywords = map(lambda keyword: keyword.strip('\n').strip('\r'), sslKeywordsFile.readlines())
        with open('analysis/data/HardcodedSSHKeys.txt', 'r') as sshKeywordsFile:
            sshKeywords = map(lambda keyword: keyword.strip('\n').strip('\r'), sshKeywordsFile.readlines())

        sslFiles = self.findFiles(sslKeywords)
        sshFiles = self.findFiles(sshKeywords)

        return sslFiles, sshFiles
    
    def findFiles(self, keywords):
        """
        Finds the files in the firmwalker output according to the keywords
        and returns an array of such files in 'outputFiles'.
        """

        files = []
        with open('analysis_result/firmwalkerOutput.txt', 'r') as firmwalker:
            for keyword in keywords:
                for line in firmwalker:
                    if line.startswith(keyword):
                        while 1:
                            dirFile = next(firmwalker)
                            if dirFile != '\n':
                                files.append(dirFile.strip('d/').strip('\n'))
                            else:
                                break
                firmwalker.seek(0)

        return files
            