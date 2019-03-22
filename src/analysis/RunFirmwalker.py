"""
Runs firmwalker on extracted firmware
"""

import os

class RunFirmwalker:

    def __init__(self, firmwareFolder):
        """
        firmwareFolder: folder name of the extracted firmware
        """
        self.firmwareFolder = firmwareFolder
    
    def run(self):
        """
        Runs firmwalker (assumes that firmwalker is installed in the root folder)
        Firmwalker output is in src/analysis_result/firmwalkerOutput.txt
        """
        savedPath = os.getcwd()
        os.chdir("../firmwalker") # firmwalker needs to be run in its directory

        # Running in firmwalker directory
        firmwarePath = "../src/analysis_result/" + self.firmwareFolder
        outputPath = "../src/analysis_result/firmwalkerOutput.txt"
        os.system("./firmwalker.sh " + firmwarePath + " " + outputPath)

        os.chdir(savedPath)

