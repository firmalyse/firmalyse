"""
Checks if any password files found have weak passwords in them
"""

import os
import subprocess

class CheckPasswords:

	def __init__(self, firmwareFolder):
		"""
		firmwareFolder: folder name of the extracted firmware
		"""
		self.firmwareFolder = firmwareFolder

		self.result = {
			'name': 'Checks for weak passwords in the firmware',
			'description': 'Weak passwords included in firmware make devices vulnerable and may allow them to be compromised. \
			This module checks for existing password hashes in the firmware and compares them against lists of common/default passwords.',
			'issues': []
		}

	def run(self):
		pwdFileDirs = self._getPwdFileDirs()

                """
                example path: ./squashfs-root/etc/passwd
                current directory: src
                """
		# os.chdir("./analysis_result/" + self.firmwareFolder)
		# for path in pwdFileDirs:
		#	self._runJohn(path)
		examplePath = "./analysis/data/example_shadow.txt"
		self.result['issues'].append(self._runJohn(examplePath))		

		# reset working directory	
		# os.chdir("../..")

	def _runJohn(self, path):
		"""
		current directory: src/analysis_result/<firmware folder>
		"""
		pwdlistdir = "./analysis/data/"
		pwdlist = "default-passwords.txt"
		issues = {'issueName': 'Default Passwords', 'Present': False, 'Usernames': []}

		subprocess.check_output(["john --wordlist=" + pwdlistdir + pwdlist + " " + path], shell=True)
		proc = subprocess.check_output(["john --show " + path + " | grep -P \"^([0-9a-zA-Z]*:)+\""], shell=True)
		if len(proc) == 0:
			return issues

		issues['Present'] = True
		for user in proc.splitlines():
			username = user.split(":")[0]
			issues['Usernames'].append(username)

		return issues

	def _getPwdFileDirs(self):
		with open("analysis_result/firmwalkerOutput.txt", "r") as f:
			pwdFiles = list()

			line = f.readline().strip()
                        while not "##################################### shadow" in line:
				line = f.readline().strip()
			line = f.readline().strip()

			while line != "":
				pwdFiles.append(line)
				line = f.readline().strip()
			
		return [self.fixPathName(path) for path in pwdFiles]

	def fixPathName(self, path):
        	if path[0] == 'd':
                	return path.replace('d', '.', 1)
        	else:
                	return path
