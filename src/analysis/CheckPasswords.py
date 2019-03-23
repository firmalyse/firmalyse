"""
Checks if any password files found have weak passwords in them
"""

import os

from AnalyzerMain import fixPathNames

class CheckPasswords:

	def __init__(self, firmwareFolder):
		"""
		firmwareFolder: folder name of the extracted firmware
		"""
		self.firmwareFolder = firmwareFolder

	def runChecks(self):
		pwdFiles = self._getPwdFiles()
		pwdFilePaths = [fixPathNames(path) for path in pwdFiles]

	def _getPwdFiles(self):
		with open("analysis_result/firmwalkerOutput.txt", "r") as f:
			pwdFiles = list()

			line = f.readline().strip()
			# read till start of list
			while not "##################################### passwd" in line:
				line = f.readline().strip()
			line = f.readline().strip()

			while line != "":
				pwdFiles.append(line)
				line = f.readline().strip()
			
                        while not "##################################### shadow" in line:
				line = f.readline().strip()
			line = f.readline().strip()

			while line != "":
				pwdFiles.append(line)
				line = f.readline().strip()
			
			while not "##################################### *.psk" in line:
				line = f.readline().strip()
			line = f.readline().strip()

			while line != "":
				pwdFiles.append(line)
				line = f.readline().strip()


		return pwdFiles


