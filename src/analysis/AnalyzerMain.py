"""
Main file for start of analysis (extract firmware, run analysis modules)
"""

from ExtractFirmware import ExtractFirmware
from RunFirmwalker import RunFirmwalker
from HardcodedKeys import HardcodedKeys
from CheckBinVersions import CheckBinVersions

class AnalyzerMain:

    def __init__(self, imageFile):
        """
        imageFile: firmware image that user uploaded
        """
        self.imageFile = imageFile
        self.analysisResult = []

    def start_analysis(self):
        """
        insert analysis modules here
        TODO: find way to store the analysis results and then render back to user (ASYNC? or just SYNC lol)
        """

        # Extract firmware image
        extractFirmware = ExtractFirmware(self.imageFile)
        extractFirmware.extract()
        extractedFirmwareFolder = "_" + self.imageFile.filename + ".extracted"

        # Run firmwalker on extracted firmware
        runFirmwalker = RunFirmwalker(extractedFirmwareFolder)
        runFirmwalker.run() # firmwalkeroutput is in src/analysis_result/firmwalkerOutput.txt

        # Run HardcodedKeys module
        hardcodedKeys = HardcodedKeys(extractedFirmwareFolder)
        hardcodedKeys.run()

        # Run CheckBinVersions module
        checkBinVersions = CheckBinVersions(extractedFirmwareFolder)
        checkBinVersions.run()
        self.analysisResult.append(checkBinVersions.result)
