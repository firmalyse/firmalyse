"""
Main file for start of analysis (extract firmware, run analysis modules)
"""

from ExtractFirmware import ExtractFirmware

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

        extractFirmware = ExtractFirmware(self.imageFile)
        extractFirmware.extract()
        extractedFirmwareDirectory = "analysis_result/_" + self.imageFile.filename + ".extracted"
