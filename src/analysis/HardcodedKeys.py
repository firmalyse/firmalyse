"""
Search for hardcoded X.509 and SSH private keys
"""

import platform

class HardcodedKeys:

    def __init__(self, firmwareFolder):
        self.firmwareFolder = firmwareFolder

    def run(self):
        sslFilesExtracted, sshFilesExtracted = self.extractFiles()
        sslFilesResult = self.verifySSLKeys(sslFilesExtracted)
        sshFilesResult = self.verifySSHKeys(sshFilesExtracted)
        
        # Test
        print("result:")
        print(sslFilesResult)
        print(sshFilesResult)

        self.processResult(sslFilesResult, sshFilesResult)

    def processResult(self, sslFilesResult, sshFilesResult):
        #TODO: JSON result
        return

    def verifySSHKeys(self, sshFiles):
        """
        Verfies if the SSH related files contain private keys
        and returns an array of such files that are true positive.
        Uses the fact that the default SSH key name is "id_rsa" or "id_dsa" where private keys
        are embded in headers containing "PRIVATE",
        and Dropbear private key file names usually contains "host_key".
        """

        positiveFiles = []
        for filePath in sshFiles:
            if "host_key" and "dropbear" in filePath: # Dropbear
                positiveFiles.append(filePath)
            elif "id_rsa" or "id_dsa" in filePath: # SSH keys
                if ".pub" not in filePath: # Not public keys
                    with open('analysis_result/' + self.firmwareFolder + '/' + filePath, 'r') as targetFile:
                        if targetFile.read().find("PRIVATE") != -1:
                            positiveFiles.append(filePath)
        
        return positiveFiles

    def verifySSLKeys(self, sslFiles):
        """
        Verifies if the SSL related files contain private keys
        and returns an array of such files that are true positive.
        Uses the fact that SSL private keys are embded in between headers that contains "PRIVATE"
        """

        postiveFiles = []
        for filePath in sslFiles:
            with open('analysis_result/' + self.firmwareFolder + '/' + filePath, 'r') as targetFile:
                if targetFile.read().find("PRIVATE") != -1:
                    postiveFiles.append(filePath)
        
        return postiveFiles

    def extractFiles(self):

        # SSL and SSH files keywords from firmwalker
        with open('analysis/data/HardcodedSSLKeys.txt', 'r') as sslKeywordsFile:
            sslKeywords = map(lambda keyword: keyword.strip('\n'), sslKeywordsFile.readlines())
        with open('analysis/data/HardcodedSSHKeys.txt', 'r') as sshKeywordsFile:
            sshKeywords = map(lambda keyword: keyword.strip('\n'), sshKeywordsFile.readlines())

        # Test
        print("keywords:")
        print(sslKeywords)
        print(sshKeywords)

        sslFiles = self.findFiles(sslKeywords)
        sshFiles = self.findFiles(sshKeywords)

        # Test
        print("files found:")
        print(sslFiles)
        print(sshFiles)

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
            