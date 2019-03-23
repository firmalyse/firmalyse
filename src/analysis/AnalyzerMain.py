"""
Main file for start of analysis (extract firmware, run analysis modules)
"""

from ExtractFirmware import ExtractFirmware
from RunFirmwalker import RunFirmwalker
from CheckPasswords import CheckPasswords

class AnalyzerMain:

    def __init__(self, imageFile):
        """
        imageFile: firmware image that user uploaded
        """
        self.imageFile = imageFile

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

	# Check if weak passwords exist in firmware
	checkPasswords = CheckPasswords(extractedFirmwareFolder)
	checkPasswords.runChecks()
