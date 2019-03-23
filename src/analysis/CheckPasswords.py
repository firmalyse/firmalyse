"""
Checks if any password files found have weak passwords in them
"""

import os
import subprocess

from AnalysisUtils import fixPathName

class CheckPasswords:

	def __init__(self, firmwareFolder):
		"""
		firmwareFolder: folder name of the extracted firmware
		"""
		self.firmwareFolder = firmwareFolder

	def runChecks(self):
		pwdFileDirs = self._getPwdFileDirs()

                """
                example path: ./squashfs-root/etc/passwd
                current directory: src
                """
		os.chdir("./analysis_result/" + self.firmwareFolder)
		for path in pwdFileDirs:
			self._runJohn(path)
	
		# reset working directory	
		os.chdir("../..")

	def _runJohn(self, path):
		"""
		current directory: src/analysis_result/<firmware folder>
		"""
		pwdlistDir = "../../analysis/pwdlists"
		defaultPwdListPath = "/default-passwords.txt"
		commonPwdListPath = "/common-passwords.txt"
	
		proc = subprocess.Popen(["john", ])	

	def _getPwdFileDirs(self):
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


		return [fixPathName(path) for path in pwdFiles]


