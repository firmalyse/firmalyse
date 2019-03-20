"""
Main file for start of analysis (extract binary, run analysis modules)
"""

class AnalysisMain:

    def __init__(self, binaryFile):
        """
        binaryFile: firmware binary that user uploaded
        """
        self.binaryFile = binaryFile

    def start_analysis(self):
        """
        insert analysis modules here
        TODO: find way to store the analysis results and then render back to user (ASYNC? or just SYNC lol)
        """